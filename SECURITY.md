# Security policy

## Reporting a vulnerability

Please report a security problem **privately**, through GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Do not open a public issue or a public pull request for a vulnerability, and do not put exploit details in a public discussion.

The only channel is GitHub's private vulnerability reporting. There is no e-mail address for reports, on purpose.

Please include what you looked at (a file and a section of the documents, or a test vector), what you expected, what you found, and, if you can, the exact input (bytes or a JSON string) that shows it. Describe the steps in words. Please do not send a modified copy of the code or a new test file: the licence does not allow changing the code or building new works on it.

## What is in scope

- The Rust core in `native/core` (cryptographic constructions, wire formats, parsers).
- The protocol documents in `docs/native/protocol` and the test vectors in `docs/native/vectors`: a mistake or an ambiguity in a document that would make an implementation insecure or incompatible counts.
- The protocol as the closed-source apps and server use it: the apps and the server are built on this core, so a weakness in the design described here most likely applies to them too (this repository cannot show that), and a private report is the right way to say so.
- The weaknesses already known are listed in the README table «Known limitations and what is being done». A report on one of them is still welcome if it shows more than the table says.

The iOS app and the server are **not** published, so their code cannot be reviewed from here. Please report what you find by reading the code, the documents and the vectors, and what you see in your own account in the App Store app. This policy gives no permission to attack, probe or load the service and promises no safe harbour; do not read, change or disrupt anyone else's data.

## What to expect

mr.enzo is made by one developer, and it has had **no outside security audit**. There is no bug bounty and no promised response time. Reports are read by the developer.

## Supported versions

The current branch of this repository, and the newest version of the app in the App Store.
