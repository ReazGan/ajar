package main

// service describes a locally-hostable AI service that is commonly left exposed
// with no authentication. probePath is requested over HTTP; if the response
// matches, the service is considered present. Most of these ship with auth OFF
// by default, which is the whole point of the scan.
type service struct {
	name      string
	port      int
	probePath string
	// match: all of these substrings must appear in the response body (or, for
	// a header match, "Header: value").
	bodyNeedles []string
	// risk explains why an exposed instance is dangerous.
	risk     string
	severity severity
}

var services = []service{
	{
		name: "Ollama", port: 11434, probePath: "/api/tags",
		bodyNeedles: []string{"\"models\""},
		risk:        "Anyone who can reach it can pull and run models, use your GPU, and read or delete your local models. Ollama ships with no authentication.",
		severity:    high,
	},
	{
		name: "ComfyUI", port: 8188, probePath: "/system_stats",
		bodyNeedles: []string{"system", "devices"},
		risk:        "ComfyUI custom nodes can run arbitrary Python, so an exposed instance is effectively remote code execution on the host.",
		severity:    critical,
	},
	{
		name: "Stable Diffusion WebUI (A1111)", port: 7860, probePath: "/sdapi/v1/sd-models",
		bodyNeedles: []string{"model_name", "filename"},
		risk:        "The API can load models and, with common extensions, run scripts on the host. It has no authentication unless you add --gradio-auth.",
		severity:    critical,
	},
	{
		name: "vLLM / OpenAI-compatible server", port: 8000, probePath: "/v1/models",
		bodyNeedles: []string{"\"data\"", "\"object\""},
		risk:        "An open OpenAI-compatible endpoint lets anyone use your GPU and models for free, and may expose model paths. Put it behind an API key or a proxy.",
		severity:    high,
	},
	{
		name: "LocalAI", port: 8080, probePath: "/v1/models",
		bodyNeedles: []string{"\"data\"", "\"object\""},
		risk:        "Anyone who can reach it can run inference on your hardware, and some backends allow loading arbitrary model files.",
		severity:    high,
	},
	{
		name: "LM Studio server", port: 1234, probePath: "/v1/models",
		bodyNeedles: []string{"\"data\"", "\"object\""},
		risk:        "An open LM Studio server lets anyone use your loaded models and GPU. Bind it to localhost instead of 0.0.0.0.",
		severity:    high,
	},
	{
		name: "text-generation-webui API", port: 5000, probePath: "/v1/models",
		bodyNeedles: []string{"\"data\""},
		risk:        "The API can load models and, with some settings, execute code. It has no auth by default.",
		severity:    critical,
	},
	{
		name: "Jupyter (no token)", port: 8888, probePath: "/api/status",
		bodyNeedles: []string{"\"started\"", "version"},
		risk:        "An open Jupyter server without a token is full remote code execution as your user. Set a password or token.",
		severity:    critical,
	},
}
