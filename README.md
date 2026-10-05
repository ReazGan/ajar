# ajar

[![CI](https://github.com/ReazGan/ajar/actions/workflows/ci.yml/badge.svg)](https://github.com/ReazGan/ajar/actions/workflows/ci.yml)

Find the local AI servers you left open.

People run Ollama, ComfyUI, Stable Diffusion WebUI, vLLM and friends on their
own machine, bind them to `0.0.0.0` "just to test from my phone", and forget.
Most of them ship with no authentication, and some (ComfyUI, A1111, Jupyter) are
remote code execution the moment they're reachable. ajar checks a host or your
network and tells you which ones are answering with no auth.

Single binary. No dependencies.

![ajar finding an exposed ComfyUI, Stable Diffusion WebUI and Ollama](https://raw.githubusercontent.com/ReazGan/ajar/main/docs/screenshot.svg)

> Only scan hosts and networks you own or are authorised to test.

## Install

Grab a binary from [Releases](https://github.com/ReazGan/ajar/releases), or with
Go 1.22+:

```
go install github.com/ReazGan/ajar@latest
```

## Usage

```
ajar                     scan 127.0.0.1
ajar 192.168.1.50        scan one host
ajar 192.168.1.0/24      scan a local network you own
ajar --json              machine-readable output
```

Exit status is `0` when nothing is exposed, `1` when something is, and `2` on
error, so it drops into a cron check of your own box.

## What it looks for

| Service | Default port | If exposed |
|---------|--------------|------------|
| Ollama | 11434 | anyone can use your GPU and models |
| ComfyUI | 8188 | arbitrary Python (RCE) via custom nodes |
| Stable Diffusion WebUI (A1111) | 7860 | model loading and, with extensions, RCE |
| vLLM / OpenAI-compatible | 8000 | free use of your GPU and models |
| LocalAI | 8080 | inference on your hardware |
| LM Studio | 1234 | your loaded models and GPU |
| text-generation-webui | 5000 | model loading, possible code execution |
| Jupyter (no token) | 8888 | full RCE as your user |

A service that answers with `401`/`403` is treated as protected and not
reported; ajar only flags ones that respond with no authentication.

## License

MIT
