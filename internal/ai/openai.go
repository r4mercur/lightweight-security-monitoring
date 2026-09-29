package ai

import (
	"context"
	"lightweight-security-monitoring/internal/domain"
	"net/http"
	"strings"
)

// openAIAnalyzer uses the OpenAI Responses API with structured outputs
// (text.format json_schema). The Responses API serves every current OpenAI
// model, including ones not offered via Chat Completions (e.g. gpt-5.6-cyber).
type openAIAnalyzer struct {
	apiKey     string
	model      string
	url        string
	httpClient *http.Client
}

const defaultOpenAIURL = "https://api.openai.com/v1"

func newOpenAI(cfg Config) *openAIAnalyzer {
	base := cfg.BaseURL
	if base == "" {
		base = defaultOpenAIURL
	}
	return &openAIAnalyzer{
		apiKey:     cfg.OpenAIKey,
		model:      cfg.Model,
		url:        strings.TrimSuffix(base, "/") + "/responses",
		httpClient: &http.Client{Timeout: cfg.Timeout},
	}
}

func (a *openAIAnalyzer) Provider() string { return ProviderOpenAI }
func (a *openAIAnalyzer) Model() string    { return a.model }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (a *openAIAnalyzer) Analyze(ctx context.Context, alert domain.Alert, event domain.Event) (domain.AIAnalysis, error) {
	body := map[string]any{
		"model":        a.model,
		"instructions": systemPrompt,
		"input":        []chatMessage{{Role: "user", Content: userMessage(alert, event)}},
		"text": map[string]any{
			"format": map[string]any{
				"type":   "json_schema",
				"name":   "alert_analysis",
				"strict": true,
				"schema": resultSchema,
			},
		},
		"store": false, // do not keep the (attacker-supplied) event data on OpenAI's side
	}

	var resp struct {
		Status            string `json:"status"`
		IncompleteDetails *struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Type    string `json:"type"`
				Text    string `json:"text"`
				Refusal string `json:"refusal"`
			} `json:"content"`
		} `json:"output"`
	}
	headers := map[string]string{"Authorization": "Bearer " + a.apiKey}
	if err := postJSON(ctx, a.httpClient, a.url, headers, body, &resp); err != nil {
		return domain.AIAnalysis{}, err
	}
	if resp.Status == "incomplete" && resp.IncompleteDetails != nil && resp.IncompleteDetails.Reason == "max_output_tokens" {
		return domain.AIAnalysis{}, errTruncated
	}

	// Output may contain reasoning items before the message; collect its text.
	var text strings.Builder
	for _, item := range resp.Output {
		if item.Type != "message" {
			continue
		}
		for _, c := range item.Content {
			switch c.Type {
			case "refusal":
				return domain.AIAnalysis{}, wrapRefusal(c.Refusal)
			case "output_text":
				text.WriteString(c.Text)
			}
		}
	}
	if text.Len() == 0 {
		return domain.AIAnalysis{}, errEmptyAnswer
	}
	return parseResult(text.String())
}
