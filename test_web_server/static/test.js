async function testFetch() {
    console.log('-=-=- testFetch -=-=-');
    try {
        const response = await fetch('https://jsonplaceholder.typicode.com/posts/1');
        const data = await response.text();
        console.log(data);
    } catch (error) {
        console.log(error);
    }
    console.log('-=-=- testFetch returned -=-=-');
}
async function testFetchCollocatedH3() {
    console.log('-=-=- testFetchCollocatedH3 -=-=-');
    try {
        const response = await fetch(
            'https://localhost:4433/i/', 
            {
                "abyss-collocated-http3" : true,
            }
        );
        const data = await response.text();
        console.log("status: " + response.statusText);
        console.log(response.status)
        console.log(data);
    } catch (error) {
        console.log(error);
    }
    console.log('-=-=- testFetchCollocatedH3 returned -=-=-');
}
async function testAll() {
    await testFetch();
    await testFetchCollocatedH3();
}
testFetchCollocatedH3();