package keywordextractor

import (
	"fmt" // Added for fmt.Errorf
	"strings"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"golang.org/x/net/html"
)

// KeywordExtractionResult holds the details of a single keyword match.
type KeywordExtractionResult struct {
	MatchedPattern string   `json:"matchedPattern"` // The pattern from the rule (e.g., the regex string or keyword string)
	MatchedText    string   `json:"matchedText"`    // The actual text that matched
	Category       string   `json:"category,omitempty"`
	// Count          int      `json:"count"` // Count might be better handled by the caller if aggregating results
	Contexts []string `json:"contexts,omitempty"` // Snippets of text around the match
}

// CleanHTMLToText parses HTML content and extracts clean, searchable text.
func CleanHTMLToText(htmlBody string) (string, error) {
	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.TextNode {
			trimmedData := strings.TrimSpace(n.Data)
			if trimmedData != "" {
				sb.WriteString(trimmedData)
				sb.WriteString(" ") // Add a space to separate text from different nodes
			}
		} else if n.Type == html.ElementNode &&
			(n.Data == "script" || n.Data == "style" || n.Data == "noscript" || n.Data == "head" || n.Data == "title" || n.Data == "nav" || n.Data == "footer" || n.Data == "aside") {
			return // Skip content of these tags
		} else if n.Type == html.ElementNode && n.Data == "br" {
			sb.WriteString(" ") // Treat <br> as a space
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}

		// Add extra space for common block elements after their content is processed
		if n.Type == html.ElementNode {
			switch n.Data {
			case "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "article", "section", "header": // Removed footer, aside, nav as they are skipped above
				sb.WriteString(" ")
			}
		}
	}

	extract(doc)

	// Consolidate multiple spaces into one, and trim.
	cleanedText := strings.Join(strings.Fields(sb.String()), " ")
	return cleanedText, nil
}

// ExtractKeywords extracts keywords from HTML content based on a set of rules.
func ExtractKeywords(htmlContent []byte, rules []config.KeywordRule) ([]KeywordExtractionResult, error) {
	results := []KeywordExtractionResult{}

	plainTextContent, err := CleanHTMLToText(string(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to clean HTML content: %w", err)
	}

	if strings.TrimSpace(plainTextContent) == "" {
		return results, nil // No text content to search
	}

	for _, rule := range rules {
		var allMatches [][]int // Stores start and end indices of matches

		if strings.ToLower(rule.Type) == "regex" {
			if rule.CompiledRegex != nil {
				allMatches = rule.CompiledRegex.FindAllStringIndex(plainTextContent, -1)
			}
		} else if strings.ToLower(rule.Type) == "string" {
			searchPattern := rule.Pattern
			textContentToSearch := plainTextContent
			if !rule.CaseSensitive {
				searchPattern = strings.ToLower(searchPattern)
				textContentToSearch = strings.ToLower(textContentToSearch)
			}
			idx := 0
			for {
				foundIdx := strings.Index(textContentToSearch[idx:], searchPattern)
				if foundIdx == -1 {
					break
				}
				actualFoundIdx := idx + foundIdx
				allMatches = append(allMatches, []int{actualFoundIdx, actualFoundIdx + len(searchPattern)})
				idx = actualFoundIdx + len(searchPattern)
				if idx >= len(textContentToSearch) {
				    break
				}
			}
		} else {
			// Log or handle unknown rule type if necessary, though config loading should warn
			continue
		}

		for _, matchIndices := range allMatches {
			start := matchIndices[0]
			end := matchIndices[1]
			matchedText := plainTextContent[start:end]

			var contexts []string
			if rule.ContextChars > 0 {
				contextStart := start - rule.ContextChars
				if contextStart < 0 {
					contextStart = 0
				}
				contextEnd := end + rule.ContextChars
				if contextEnd > len(plainTextContent) {
					contextEnd = len(plainTextContent)
				}
				contexts = append(contexts, plainTextContent[contextStart:contextEnd])
			}

			// Check if this exact match (text and position) has already been added by a similar or overlapping rule
			// This is a simple check; more sophisticated de-duplication might be needed if rules can be very similar.
			// For now, we add all matches from all rules.
			result := KeywordExtractionResult{
				MatchedPattern: rule.Pattern, // Store original pattern
				MatchedText:    matchedText,
				Category:       rule.Category,
				Contexts:       contexts,
			}
			results = append(results, result)
		}
	}

	return results, nil
}
