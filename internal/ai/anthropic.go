package ai

import (
	"context"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/domain"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// anthropicAnalyzer uses the Claude Messages API via the official SDK, with
// structured outputs so the answer always matches resultSchema.
type anthropicAnalyzer struct {
	client anthropic.Client
	model  string
	effort anthropic.OutputConfigEffort
}

// anthropicMaxTokens leaves room for the model's (adaptive) thinking in addition
// to the short JSON answer.
const anthropicMaxTokens = 4096

func newAnthropic(cfg Config) *anthropicAnalyzer {
	opts := []option.RequestOption{option.WithRequestTimeout(cfg.Timeout)}
	if cfg.AnthropicKey != "" {
		opts = append(opts, option.WithAPIKey(cfg.AnthropicKey))
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}
	a := &anthropicAnalyzer{client: anthropic.NewClient(opts...), model: cfg.Model}
	if cfg.Effort != "none" {
		a.effort = anthropic.OutputConfigEffort(cfg.Effort)
	}
	return a
}

func (a *anthropicAnalyzer) Provider() string { return ProviderAnthropic }
func (a *anthropicAnalyzer) Model() string    { return a.model }

func (a *anthropicAnalyzer) Analyze(ctx context.Context, alert domain.Alert, event domain.Event) (domain.AIAnalysis, error) {
	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: anthropicMaxTokens,
		System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userMessage(alert, event))),
		},
		OutputConfig: anthropic.OutputConfigParam{
			Effort: a.effort, // omitted when empty
			Format: anthropic.JSONOutputFormatParam{Schema: resultSchema},
		},
	})
	if err != nil {
		if apiErr, ok := errors.AsType[*anthropic.Error](err); ok {
			return domain.AIAnalysis{}, fmt.Errorf("anthropic API returned %d: %w", apiErr.StatusCode, err)
		}
		return domain.AIAnalysis{}, fmt.Errorf("calling anthropic API: %w", err)
	}

	switch resp.StopReason {
	case anthropic.StopReasonRefusal:
		category := string(resp.StopDetails.Category)
		if category == "" {
			category = "unspecified"
		}
		return domain.AIAnalysis{}, fmt.Errorf("%w (category %s)", ErrRefused, category)
	case anthropic.StopReasonMaxTokens:
		return domain.AIAnalysis{}, errTruncated
	}

	var text strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	return parseResult(text.String())
}
