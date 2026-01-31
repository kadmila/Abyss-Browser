using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using UnityEngine;
using UnityEngine.UIElements;

namespace ClientUtils.UIManager
{
    public class UIManager : IDisposable
    {
        private UIResources uiResources;
        private UIDocument uiDocument;

        //internal uiDocument reference shortcuts
        private VisualElement root;
        private TextField addressBar;
        private TextField sub_addressBar;
        private Label localAddrLabel;
        private Label extraLabel;
        private Button infoResetButton;
        private TextField consoleInputBar;
        private Label frameTime;
        private Label debugStack;

        private bool _is_active;
        private LinkedList<string> _console_lines;
        private bool _is_console_updated;

        //publics
        public string AddressBarText => addressBar.text;
        public string SubAddressBarText => addressBar.text;

        public LocalItemSection LocalItemSection;
        public MemberItemSection MemberItemSection;
        public MemberProfileSection MemberProfileSection;

        //callback reservation
        public Action<string> OnAddressBarSubmit;
        public Action<string> OnSubAddressBarSubmit;
        public Action<string> OnConsoleCommand;

        public UIManager(UIResources UIResources, UIDocument UIDocument)
        {
            uiResources = UIResources;
            uiDocument = UIDocument;

            //locate all elements
            root = uiDocument.rootVisualElement;

            addressBar = UQueryExtensions.Q<TextField>(root, "address-bar");
            addressBar.RegisterCallback<KeyDownEvent>(x =>
            {
                Debug.Log("address bar key down!");
                if (x.keyCode == KeyCode.Return)
                    OnAddressBarSubmit(addressBar.value);
            });

            sub_addressBar = UQueryExtensions.Q<TextField>(root, "sub-address-bar");
            sub_addressBar.RegisterCallback<KeyDownEvent>(x =>
            {
                if (x.keyCode == KeyCode.Return)
                    OnSubAddressBarSubmit(sub_addressBar.value);
            });

            localAddrLabel = UQueryExtensions.Q<Label>(root, "info");

            extraLabel = UQueryExtensions.Q<Label>(root, "info-more");
            infoResetButton = UQueryExtensions.Q<Button>(root, "terminal-clear-button");
            infoResetButton.clicked += ClearConsole;

            consoleInputBar = UQueryExtensions.Q<TextField>(root, "console-input-bar");
            consoleInputBar.RegisterCallback<KeyDownEvent>(x =>
            {
                if (x.keyCode == KeyCode.Return)
                    OnConsoleCommand(consoleInputBar.value);
            });

            frameTime = UQueryExtensions.Q<Label>(root, "frame-time");
            debugStack = UQueryExtensions.Q<Label>(root, "debug-stack");

            LocalItemSection = new(UQueryExtensions.Q(root, "itembar"), uiResources.DefaultItemIcon);

            MemberItemSection = new(UQueryExtensions.Q(root, "memberitemsection"), uiResources.DefaultItemIcon);

            MemberProfileSection = new(UQueryExtensions.Q(root, "memberprofilesection"), uiResources.DefaultMemberProfile);
            MemberProfileSection.RegisterClickCallback(peer_hash =>
            {
                MemberItemSection.Show(peer_hash);
            });

            if (localAddrLabel == null || extraLabel == null)
            {
                Debug.LogError("UI components not found!");
            }

            //default event handler - this should not be called.
            OnAddressBarSubmit = (arg) => { };
            OnSubAddressBarSubmit = (arg) => { };
            OnConsoleCommand = (arg) => { };

            _console_lines = new();
            _is_console_updated = false;

            var null_mem = FirstNullMemberName();
            if (null_mem != string.Empty)
                Debug.Log("haha " + null_mem + " is null");

            Activate();
        }
        public string FirstNullMemberName()
        {
            var fields = this.GetType().GetFields(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);

            foreach (var field in fields)
                if (field.GetValue(this) == null)
                    return field.Name;

            return string.Empty;
        }
        public void UnityUpdate()
        {
            if (_is_active && _is_console_updated)
            {
                lock (_console_lines)
                {
                    extraLabel.text = string.Join("\n", _console_lines);
                }
                _is_console_updated = false;
            }
        }
        public void Activate()
        {
            _is_active = true;
            root.visible = true;
            addressBar.focusable = true;
        }
        public void Deactivate()
        {
            _is_active = false;
            MemberItemSection.Hide();
            root.visible = false;
            addressBar.focusable = false;
        }
        public void AppendConsole(string line)
        {
            ClientLogger.WriteLine(line);

            lock (_console_lines)
            {
                _ = _console_lines.AddLast(line);
                if (_console_lines.Count == 100)
                {
                    _console_lines.RemoveFirst();
                }
                _is_console_updated = true;
            }
        }
        private void ClearConsole()
        {
            lock (_console_lines)
            {
                _console_lines.Clear();
                _is_console_updated = true;
            }
        }
        public void SetWorldIcon(Texture2D texture)
        {
            root.style.backgroundImage = texture;
        }
        public void ClearWorldIcon()
        {
            root.style.backgroundImage = null;
        }
        public void SetLocalInfo(string hash)
        {
            localAddrLabel.text = hash;
        }
        public void SetFrameTime(string info)
        {
            frameTime.text = info;
        }

        public void DebugEnter(string msg)
        {
            debugStack.text = debugStack.text + "->" + msg;
        }
        public void DebugLeave(string msg)
        {
            if (debugStack.text.EndsWith("->" + msg))
            {
                debugStack.text = debugStack.text[..(debugStack.text.Length - msg.Length - 2)];
            }
            else
            {
                debugStack.text = debugStack.text + "(X-)" + msg;
            }
        }

        public void Dispose()
        {
            uiResources = null;
            uiDocument = null;

            root = null;
            addressBar = null;
            sub_addressBar = null;
            localAddrLabel = null;
            extraLabel = null;
            consoleInputBar = null;

            LocalItemSection = null;
            MemberItemSection = null;
            MemberProfileSection = null;

            OnAddressBarSubmit = null;
            OnSubAddressBarSubmit = null;
            OnConsoleCommand = null;

            _console_lines = null;

            GC.SuppressFinalize(this);
        }
        ~UIManager() => Dispose();
    }

}
