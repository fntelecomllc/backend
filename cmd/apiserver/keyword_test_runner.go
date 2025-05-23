package main

import (
	"fmt"
	"log"
	"regexp"

	"github.com/fntelecomllc/domainflow/backend/internal/config"
	"github.com/fntelecomllc/domainflow/backend/internal/keywordextractor"
)

func main() {
	fmt.Println("--- Running Keyword Extractor Standalone Test ---")

	// Manually define rules, similar to what would be loaded from config
	// For regex, compile them directly here for the test
	compiledEmailRegex, err := regexp.Compile("(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
	if err != nil {
		log.Fatalf("Failed to compile test regex: %v", err)
	}

	testRules := []config.KeywordRule{
		{Pattern: "contact us", Type: "string", CaseSensitive: false, Category: "Contact", ContextChars: 20},
		{Pattern: "Privacy Policy", Type: "string", CaseSensitive: true, Category: "Legal", ContextChars: 30},
		{Pattern: "example@example.com", Type: "string", CaseSensitive: false, Category: "DirectEmailString", ContextChars: 15}, // Test specific string match for an email
		{
			Pattern:       compiledEmailRegex.String(), // Store the original pattern string
			Type:          "regex",
			CaseSensitive: false, // Handled by (?i) in regex pattern
			Category:      "EmailRegex",
			ContextChars:  25,
			CompiledRegex: compiledEmailRegex,
		},
	}

	sampleHTML := `
	<html>
		<head>
			<title>My Test Page</title>
			<script>console.log("skip me");</script>
			<style>.skip { color: blue; }</style>
		</head>
		<body>
			<h1>Welcome</h1>
			<p>This is a test page. Please <a href="/contact">contact us</a> if you have questions.</p>
			<p>You can also email us at info@example.com or reach out to support@example.com for help.</p>
			<p>Another mention of contact us here!</p>
			<div>
				<p>Check our Privacy Policy for more details. And our privacy policy is important.</p>
				<p>This is another paragraph with contact us again, and test@example.com too.</p>
                <p>Some text around example@example.com to see context.</p>
			</div>
			<nav>Should be skipped</nav>
			<footer>Also skipped footer content. Email in footer: footer@example.com</footer>
		</body>
	</html>
	`

	fmt.Println("\n[Test 1: Basic HTML]")
	cleanedText, err := keywordextractor.CleanHTMLToText(sampleHTML)
	if err != nil {
		fmt.Printf("Error cleaning HTML: %v\n", err)
	} else {
		fmt.Printf("Cleaned Text:\n---\n%s\n---\n", cleanedText)
	}

	results, err := keywordextractor.ExtractKeywords([]byte(sampleHTML), testRules)
	if err != nil {
		fmt.Printf("Error extracting keywords: %v\n", err)
	} else {
		fmt.Printf("\nFound %d keyword matches:\n", len(results))
		for i, res := range results {
			fmt.Printf("  %d. Pattern: '%s', Matched: '%s', Category: '%s'\n", i+1, res.MatchedPattern, res.MatchedText, res.Category)
			fmt.Printf("     Contexts: %v\n", res.Contexts)
		}
	}

	sampleHTML2 := `<p>No relevant keywords here, just some plain text.</p>`
	fmt.Println("\n[Test 2: No Matches]")
	cleanedText2, _ := keywordextractor.CleanHTMLToText(sampleHTML2)
	fmt.Printf("Cleaned Text 2:\n---\n%s\n---\n", cleanedText2)
	results2, err := keywordextractor.ExtractKeywords([]byte(sampleHTML2), testRules)
	if err != nil {
		fmt.Printf("Error extracting keywords: %v\n", err)
	} else {
		fmt.Printf("\nFound %d keyword matches.\n", len(results2))
	}

	emptyHTML := `<body><script>var x=1;</script><style>body{margin:0}</style><!-- comment --></body>`
	fmt.Println("\n[Test 3: Empty Visible Content]")
	cleanedText3, _ := keywordextractor.CleanHTMLToText(emptyHTML)
	fmt.Printf("Cleaned Text 3:\n---\n%s\n---\n", cleanedText3)
	results3, err := keywordextractor.ExtractKeywords([]byte(emptyHTML), testRules)
	if err != nil {
		fmt.Printf("Error extracting keywords: %v\n", err)
	} else {
		fmt.Printf("\nFound %d keyword matches.\n", len(results3))
	}

	fmt.Println("\n--- Keyword Extractor Standalone Test Complete ---")
}
