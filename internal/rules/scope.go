package rules

func buildProtectedRanges(lines []string, scopeRe compiledMatcher) map[int]bool {
	protected := make(map[int]bool)
	if scopeRe == nil {
		return protected
	}

	for index := 0; index < len(lines); {
		lineNumber := index + 1
		line := lines[index]
		if !scopeRe.MatchString(line) {
			index++
			continue
		}

		nextIndex, protectedLines := protectedScopeLines(lines, index, countBraces(line))
		protected[lineNumber] = true
		for _, protectedLine := range protectedLines {
			protected[protectedLine] = true
		}
		index = nextIndex
	}

	return protected
}

func protectedScopeLines(lines []string, startIndex int, depth int) (int, []int) {
	if depth > 0 {
		return consumeOpenScope(lines, startIndex+1, depth)
	}

	protectedLines := []int{}
	nextIndex := startIndex + 1
	for nextIndex < len(lines) {
		depth += countBraces(lines[nextIndex])
		protectedLines = append(protectedLines, nextIndex+1)
		nextIndex++
		if depth > 0 {
			break
		}
	}

	if depth <= 0 {
		return nextIndex, protectedLines
	}

	finalIndex, nested := consumeOpenScope(lines, nextIndex, depth)
	return finalIndex, append(protectedLines, nested...)
}

func consumeOpenScope(lines []string, index int, depth int) (int, []int) {
	protectedLines := []int{}
	for index < len(lines) && depth > 0 {
		depth += countBraces(lines[index])
		if depth > 0 {
			protectedLines = append(protectedLines, index+1)
		}
		index++
	}
	return index, protectedLines
}

func countBraces(line string) int {
	depth := 0
	inSingleQuotedString := false
	inDoubleQuotedString := false

	for index := 0; index < len(line); index++ {
		character := line[index]
		if character == '\\' && (inSingleQuotedString || inDoubleQuotedString) {
			index++
			continue
		}

		switch {
		case character == '\'' && !inDoubleQuotedString:
			inSingleQuotedString = !inSingleQuotedString
		case character == '"' && !inSingleQuotedString:
			inDoubleQuotedString = !inDoubleQuotedString
		case character == '{' && !inSingleQuotedString && !inDoubleQuotedString:
			depth++
		case character == '}' && !inSingleQuotedString && !inDoubleQuotedString:
			depth--
		}
	}

	return depth
}
