# Secure Link filter

Secure Link is a WebAssembly (WASM) filter written in
[AssemblyScript](https://docs.assemblyscript.org/) which checks the authenticity
of requested links and protects resources from unauthorized access. Authenticity
is verified by comparing the checksum value passed in a request with the value
computed for the request, using the shared secret.

This filter is *experimental* / proof-of-concept. It is not meant to be used in
production deployments.

It was inspired by nginx's [Secure Link][ngx_http_secure_link_url] module.

## Requirements

* [Envoy proxy][envoy_url] with WebAssembly support (i.e., [envoyproxy/envoy-wasm][envoy_wasm_url])

This filter has been tested with Envoy v1.13. It is possible that the filter
is compatible with newer versions, but it is untested.

## Installation

The filter can be manually compiled, or installed from
[WebAssemblyHub.io][webassembly_hub_url].

### Compiling

Compiling the filter requires [`npm`](https://www.npmjs.com/) to be installed.

First, clone this repository.

```shell
git clone --single-branch https://github.com/blake/secure-link-filter.git
```

Next, install the required dependencies.

```shell
cd envoy-secure-link-filter
npm install
```

Then build the filter using `npm run`.

```shell
npm run asbuild
```

The resultant WASM filter can be found in `./build/optimized.wasm`.

### WebAssembly Hub

This filter is also available on the [WebAssembly Hub][webassembly_hub_url].

First, [Install the wasme CLI][wasme_cli_install].

Then download the filter using the `wasme` client.

```shell
wasme pull webassemblyhub.io/blake/secure-link:v0.1
```

Refer to WebAssembly Hub's
[Deployment Tutorial](https://docs.solo.io/web-assembly-hub/latest/tutorial_code/deploy_tutorials/) docs for information on deploying the filter to various
target platforms.

## Configuration

The filter requires the following parameters in order to function.

1. Shared Secret
1. Comma-separated list of URL paths to protect

The configuration is defined in plain text with each parameter separated by the
pipe (`|`) symbol. For example:

```plaintext
<shared secret>|<Protected URL paths>
```

To configure the filter to use a shared secret of `WASM_rocks!` and protect the
URL paths `/downloads/` and `/private/`, the resultant configuration would
appear as follows.

```plaintext
WASM_rocks!|/downloads/,/private/
```

## Test the filter

This section assumes you already have an Envoy proxy running with the filter
properly configured.

Lets say, for example, that Envoy is listening on localhost port 8080 and we to
access a protected resource of `/downloads/videos/wasm-tutorial.mp4`. The filter
is configured with a shared secret of `WASM_rocks!`.

Generate the MD5 hash for the URL using the following:

```shell
$ echo -n 'videos/wasm-tutorial.mp4WASM_rocks!' | openssl md5 -hex
ab94570897eeba7fa391edc4da08c967
```

Issue an HTTP HEAD request using `curl` to test that you have access to the
resource.

```shell
curl --head localhost:8080/downloads/ab94570897eeba7fa391edc4da08c967/videos/wasm-tutorial.mp4
```

[envoy_url]: https://www.envoyproxy.io/
[envoy_wasm_url]: https://github.com/envoyproxy/envoy-wasm
[ngx_http_secure_link_url]: http://nginx.org/en/docs/http/ngx_http_secure_link_module.html
[proxy_runtime_url]: https://github.com/solo-io/proxy-runtime
[wasme_cli_install]: https://docs.solo.io/web-assembly-hub/latest/tutorial_code/getting_started/#install-the-wasme-cli
[webassembly_hub_url]: https://webassemblyhub.io/
