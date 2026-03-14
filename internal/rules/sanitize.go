package rules

import (
	"strings"
)

func sanitizeContent(relativePath string, fileContents string) string {
	sanitized := fileContents
	if strings.HasSuffix(relativePath, ".blade.php") {
		sanitized = stripBladeCommentsPreservingNewlines(sanitized)
	}
	if strings.HasSuffix(relativePath, ".php") {
		sanitized = stripPHPCommentsPreservingNewlines(sanitized)
	}
	return sanitized
}

func stripBladeCommentsPreservingNewlines(fileContents string) string {
	if fileContents == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(fileContents))

	for index := 0; index < len(fileContents); {
		if !strings.HasPrefix(fileContents[index:], "{{--") {
			builder.WriteByte(fileContents[index])
			index++
			continue
		}

		endIndex := strings.Index(fileContents[index+4:], "--}}")
		if endIndex < 0 {
			writeWhitespacePreservingNewlines(&builder, fileContents[index:])
			break
		}

		comment := fileContents[index : index+4+endIndex+4]
		writeWhitespacePreservingNewlines(&builder, comment)
		index += len(comment)
	}

	return builder.String()
}

func stripPHPCommentsPreservingNewlines(fileContents string) string {
	if fileContents == "" {
		return ""
	}

	input := []byte(fileContents)
	output := make([]byte, len(input))
	inSingleQuotedString := false
	inDoubleQuotedString := false
	inLineComment := false
	inBlockComment := false

	for index := 0; index < len(input); index++ {
		currentByte := input[index]
		nextByte := byte(0)
		if index+1 < len(input) {
			nextByte = input[index+1]
		}

		switch {
		case inLineComment:
			if currentByte == '\n' {
				inLineComment = false
				output[index] = '\n'
				continue
			}
			output[index] = ' '
		case inBlockComment:
			if currentByte == '*' && nextByte == '/' {
				output[index] = ' '
				output[index+1] = ' '
				index++
				inBlockComment = false
				continue
			}
			if currentByte == '\n' {
				output[index] = '\n'
				continue
			}
			output[index] = ' '
		case inSingleQuotedString:
			output[index] = currentByte
			if currentByte == '\\' && index+1 < len(input) {
				output[index+1] = input[index+1]
				index++
				continue
			}
			if currentByte == '\'' {
				inSingleQuotedString = false
			}
		case inDoubleQuotedString:
			output[index] = currentByte
			if currentByte == '\\' && index+1 < len(input) {
				output[index+1] = input[index+1]
				index++
				continue
			}
			if currentByte == '"' {
				inDoubleQuotedString = false
			}
		default:
			switch {
			case currentByte == '/' && nextByte == '/':
				output[index] = ' '
				output[index+1] = ' '
				index++
				inLineComment = true
			case currentByte == '/' && nextByte == '*':
				output[index] = ' '
				output[index+1] = ' '
				index++
				inBlockComment = true
			case currentByte == '#' && nextByte != '[':
				output[index] = ' '
				inLineComment = true
			default:
				output[index] = currentByte
				if currentByte == '\'' {
					inSingleQuotedString = true
				}
				if currentByte == '"' {
					inDoubleQuotedString = true
				}
			}
		}
	}

	return string(output)
}

func writeWhitespacePreservingNewlines(builder *strings.Builder, value string) {
	for _, character := range value {
		if character == '\n' {
			builder.WriteByte('\n')
			continue
		}
		builder.WriteByte(' ')
	}
}
