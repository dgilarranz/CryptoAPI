# CryptoAPI

This repository contains the source code of a simple PKI API implemented using Ruby
and Sinatra. It allows for the creation of Certification Authorities (CAs), as well
as the emission and validation of certificates.

## Instructions for Users

### Installation

A `Dockerfile` is provided to aid in the deployment of the CryptoAPI microservice in
any environment. In order to correctly build the Docker image, the following steps
must be performed:

1. Clone the repository:

```bash
git clone https://github.com/dgilarranz/CryptoAPI.git
cd CryptoAPI
```

2. Create a `.env` file with the desired API Key.

```bash
echo "API_KEY=$(uuidgen)" > .env
```

3. Build the docker image:

```bash
docker build -t my_custom_pki:v1 .
```

> [!CAUTION]
> For security concerns, the building process will abort if the `.env` file is not supplied.
> Furthermore, microservice will also refuse to start unless the `.env` file is present in
> its root directory. It is recommended to use a UUID or a sufficiently long hexadecimal string
> to provide brute force protection.


### Usage

In order to start the microservice, the following command must be issued:

```bash
docker run -p 8000:8000 my_custom_pki:v1
```

The microservice exposes the API documentation at the endpoint `/docs`. If deployed locally, it
can be viewd at the following URL:

- Documentation: [http://localhost:8000/docs](http://localhost:8000/docs)

> [!NOTE]
> The link will not work unless the microservice has been deployed locally.

## Instructions for Developers

### Building Locally

In order to build and test locally the project, without the need of building a docker image,
the following steps must be performed.

1. Clone the repository:

```bash
git clone https://github.com/dgilarranz/CryptoAPI.git
cd CryptoAPI
```

2. Install the dependencies, including those used for development and testing:

```bash
bundle install
```

3. Create a `.env` file with the API key:

```bash
echo "API_KEY=$(uuidgen)" > .env
```

4. Deploy a test server locally:

```bash
bundle exec puma -p 8000
```

> [!NOTE]
> The following steps require ruby 3.4.1 or higher to be installed in the development station.
> Instructions on how to install ruby can be found [here](https://www.ruby-lang.org/en/documentation/installation/).

### Running Tests

The project contains two separate groups of tests:

- **Unit tests**, created to test the internal behaviour of the developed microservice.
- **API tests**, to verify that the requests have the expected results.

In order to run the **unit tests**, the following command must be run:

```bash
bundle exec rake test:unit
```

**API tests** can be run by issuing the following command:

```bash
bundle exec rake test:api
```
