package ai

import (
	"context"
	"lightweight-security-monitoring/internal/domain"
	"net/http"
	"strings"
)

// ollamaAnalyzer uses a local model served by Ollama (native /api/chat). The
// JSON schema is passed as "format", so Ollama constrains the output to it.
// Nothing leaves the machine.
type ollamaAnalyzer struct {
	model      string
	url        string
	httpClient *http.Client
}

func newOllama(cfg Config) *ollamaAnalyzer {
	return &ollamaAnalyzer{
		model:      cfg.Model,
		url:        strings.TrimSuffix(cfg.BaseURL, "/") + "/api/chat",
		httpClient: &http.Client{Timeout: cfg.Timeout},
	}
}

func (a *ollamaAnalyzer) Provider() string { return ProviderOllama }
func (a *ollamaAnalyzer) Model() string    { return a.model }

func (a *ollamaAnalyzer) Analyze(ctx context.Context, alert domain.Alert, event domain.Event) (domain.AIAnalysis, error) {
	body := map[string]any{
		"model": a.model,
		"messages": []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userMessage(alert, event)},
		},
		"format":  resultSchema,
		"stream":  false,
		"options": map[string]any{"temperature": 0},
	}

	var resp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		DoneReason string `json:"done_reason"`
	}
	if err := postJSON(ctx, a.httpClient, a.url, nil, body, &resp); err != nil {
		return domain.AIAnalysis{}, err
	}
	if resp.DoneReason == "length" {
		return domain.AIAnalysis{}, errTruncated
	}
	if resp.Message.Content == "" {
		return domain.AIAnalysis{}, errEmptyAnswer
	}
	return parseResult(resp.Message.Content)
}
