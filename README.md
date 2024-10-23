# Jackie

![Jackie Logo](https://m.media-amazon.com/images/S/pv-target-images/458476d4ac3bc4000b481f5c40267f935075a08289786544f4018ae417f2e446._SX1080_FMjpg_.jpg) 


Jackie is a command-line tool for checking URLs for clickjacking vulnerabilities. This tool analyzes HTTP headers such as `X-Frame-Options` and `Content-Security-Policy` to determine if a URL is protected against clickjacking attacks.

## Features

- **Fast**: Fast analysis of multiple URLs using threading.
- **Color-Coded Output**: Easily distinguish between vulnerable and non-vulnerable URLs.
- **Optional Output File**: Save vulnerable URLs to a specified file.
- **User-Friendly**: Simple command-line interface that reads from stdin.

## Installation

### Prerequisites

Make sure you have Python 3.x and pip installed. You can download Python from [python.org](https://www.python.org/downloads/).

### Clone the Repository

```bash
git clone https://github.com/47hxl-53r/jackie.git
cd jackie
```

### Install Dependencies

```pip3 install -r requirements.txt```

### Usage 

```cat <file_with_urls> | python3 jackie.py [-o <output_file>]```

(For BB hunters)


```cat scope | subfinder -recursive | httpx-toolkit -mc 200 | python3 clickjacker.py -o jackie.txt```

### Options

```-o, --output: Specify a file to save vulnerable URLs.```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## Security

Report any security vulnerabilities here [Author](https://t.me/p4in000)
