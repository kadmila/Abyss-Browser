package main

import (
	"os"
	"regexp"
	"strings"
)

func main() {
	protobuf_file_path := os.Args[1]
	protobuf_title := strings.Split(protobuf_file_path, ".")[0]

	protobuf_file_raw, _ := os.ReadFile(protobuf_file_path)

	body := extractProtobufBody(string(protobuf_file_raw), protobuf_title)
	generated_code := GenerateWriterCode(body, protobuf_title)
	os.WriteFile(protobuf_title+"Writer.cs", []byte(generated_code), 0644)
}

func extractProtobufBody(data string, title string) [][]string {
	d2 := data[strings.Index(data, "message "+title):]
	d3 := d2[strings.Index(d2, "\n")+1:]
	message_define_section := strings.TrimSpace(d3[:strings.Index(d3, "oneof")])

	re := regexp.MustCompile(`[^A-Za-z/\n_0-9= ]+`)
	cleaned := re.ReplaceAllString(message_define_section, "")
	lines := strings.Split(cleaned, "\n")
	var result [][]string
	var block []string
	for _, line := range lines {
		if strings.HasPrefix(line, "message") {
			if len(block) != 0 {
				result = append(result, block)
			}
			block = make([]string, 0)
		}

		trimmed := strings.SplitN(line, "=", 2)[0]
		trimmed = strings.TrimSpace(trimmed)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if len(trimmed) == 0 {
			continue
		}
		block = append(block, trimmed)
	}
	result = append(result, block)

	return result
}

func toPascalCase(snake string) string {
	words := strings.Split(snake, "_")
	var pascalCase string
	for _, word := range words {
		if word == "" {
			continue
		}
		// Convert the first letter to uppercase and the rest to lowercase
		pascalCase += strings.ToUpper(string(word[0])) + strings.ToLower(word[1:])
	}
	return pascalCase
}

func ConvertArgument(argument_line string) string {
	if strings.HasPrefix(argument_line, "bytes ") {
		return "ByteString " + argument_line[6:]
	} else if strings.HasPrefix(argument_line, "int32 ") {
		return "int " + argument_line[6:]
	} else if strings.HasPrefix(argument_line, "repeated ") {
		splits := strings.SplitN(argument_line, " ", 3)
		return splits[1] + "[] " + splits[2]
	}
	return argument_line
}

func ConvertArgumentList(param_lines []string) string {
	var argument_lines []string
	for _, line := range param_lines {
		argument_lines = append(argument_lines, ConvertArgument(line))
	}
	return strings.Join(argument_lines, `,
			`)
}

func ConvertAssignments(param_lines []string, block_subject string) (string, string) {
	var simple_lines []string
	var manual_lines []string
	for _, line := range param_lines {
		if strings.HasPrefix(line, "repeated") {
			param_name := strings.Split(line, " ")[2]
			manual_lines = append(manual_lines,
				"action."+block_subject+
					"."+toPascalCase(param_name)+
					".Add( "+param_name+" );")
		} else {
			param_name := strings.Split(line, " ")[1]
			simple_lines = append(simple_lines,
				toPascalCase(param_name)+" = "+param_name)
		}
	}
	return strings.Join(simple_lines, `,
                    `),
		strings.Join(manual_lines, `
            `)
}

func GenerateMethod(block []string, title string) string {
	block_subject := block[0][8:]
	simple_assignment, manual_assignment := ConvertAssignments(block[1:], block_subject)
	return `
		public void ` + block_subject + `
		(
			` + ConvertArgumentList(block[1:]) + `
		)
		{
			var action = new ` + title + `
			{
				` + block_subject + ` = new()
				{
					` + simple_assignment + `
				}
			};
			` + manual_assignment + `
			Write(action);
		}`
}

func GenerateWriterCode(data [][]string, title string) string {
	var methods []string
	for _, block := range data {
		methods = append(methods, GenerateMethod(block, title))
	}

	return `
#region Designer generated code
using Google.Protobuf;
using System;
using System.CodeDom.Compiler;

namespace AbyssCLI.ABI
{
    [GeneratedCodeAttribute("` + title + `Gen", "1.0.0")]
	public class ` + title + `Writer
	{
        private readonly System.IO.Stream _stream;
        public bool AutoFlush = false;
        public ` + title + `Writer(System.IO.Stream stream)
        {
            _stream = stream;
        }
        private void Write(` + title + ` msg)
        {
            var msg_len = msg.CalculateSize();

            lock (_stream)
            {
                _stream.Write(BitConverter.GetBytes(msg_len));
                msg.WriteTo(_stream);

            }
            if (AutoFlush)
            {
                _stream.Flush();
            }
        }
		` + strings.Join(methods, "") + `
	}
}
#endregion Designer generated code
`
}
