import * as vscode from 'vscode'
import { documentation, DocEntry } from './documentation'

/**
 * Creates a formatted hover markdown for documentation
 */
function createHoverMarkdown(
	title: string,
	docEntry: DocEntry,
	options?: {
		boldDescription?: boolean
		subtitle?: string
	},
): vscode.MarkdownString {
	const markdown = new vscode.MarkdownString()

	// Title
	markdown.appendMarkdown(`### ${title}\n\n`)

	// Optional subtitle (e.g., "Disruptive Action")
	if (options?.subtitle) {
		markdown.appendMarkdown(`*${options.subtitle}*\n\n`)
	}

	// Description (optionally bold)
	const description = options?.boldDescription ? `**${docEntry.description}**` : docEntry.description
	markdown.appendMarkdown(`${description}\n\n`)

	// When to use note
	if (docEntry.whenToUse) {
		markdown.appendMarkdown(`**When to use:**\n\n${docEntry.whenToUse}\n\n`)
	}

	// Related actions
	if (docEntry.relatedActions && docEntry.relatedActions.length > 0) {
		markdown.appendMarkdown(`**Alternative actions:** ${docEntry.relatedActions.map((a) => `\`${a}\``).join(', ')}\n\n`)
	}

	// Syntax
	if (docEntry.syntax) {
		markdown.appendMarkdown(`**Syntax:**\n`)
		markdown.appendCodeblock(docEntry.syntax, 'secrules')
	}

	// Example
	if (docEntry.example) {
		markdown.appendMarkdown(`**Example:**\n`)
		markdown.appendCodeblock(docEntry.example, 'secrules')
	}

	// Documentation link
	// ctl: actions all share the same #ctl anchor, others use their name as anchor
	const anchor = title.startsWith('ctl:') ? 'ctl' : title.replace(/^@/, '')
	const wikiUrl = `https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#user-content-${anchor}`
	markdown.appendMarkdown(`\n[View full documentation](${wikiUrl})`)

	markdown.isTrusted = true
	return markdown
}

/**
 * Checks if a word appears as an action in the line
 */
function isActionInLine(word: string, lineText: string): boolean {
	const actionWithColon = new RegExp(`[,\\s"']${word}:`, 'i')
	const actionStandalone = new RegExp(`[,\\s"']${word}(?:[,\\s"']|\\\\|$)`, 'i')
	const actionAtStart = new RegExp(`^\\s*"?${word}(?:[,:\\s]|$)`, 'i')

	return !!(lineText.match(actionWithColon) || lineText.match(actionStandalone) || lineText.match(actionAtStart))
}

export function activate(context: vscode.ExtensionContext) {
	console.log('SecRules extension activated')

	// Register hover provider for secrules language
	const hoverProvider = vscode.languages.registerHoverProvider('secrules', {
		provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.ProviderResult<vscode.Hover> {
			const wordRange = document.getWordRangeAtPosition(position, /[a-zA-Z_][a-zA-Z0-9_]*/)
			if (!wordRange) {
				return undefined
			}

			const word = document.getText(wordRange)
			const lineText = document.lineAt(position.line).text
			const linePrefix = lineText.substring(0, position.character)

			// Check if this is a directive (starts with Sec)
			if (word.startsWith('Sec')) {
				const doc = documentation.directives[word]
				if (doc) {
					const markdown = createHoverMarkdown(word, doc, { boldDescription: true })
					return new vscode.Hover(markdown, wordRange)
				}
			}

			// Check for ctl: actions (like ruleRemoveTargetById)
			if (linePrefix.includes('ctl:')) {
				const ctlMatch = lineText.match(/ctl:([a-zA-Z_]+)/)
				if (ctlMatch && ctlMatch[1] === word) {
					const doc = documentation.ctlActions[word]
					if (doc) {
						const markdown = createHoverMarkdown(`ctl:${word}`, doc)
						return new vscode.Hover(markdown, wordRange)
					}
				}
			}

			// Check for actions (id, phase, msg, etc.)
			const actionDoc = documentation.actions[word]
			if (actionDoc && isActionInLine(word, lineText)) {
				const markdown = createHoverMarkdown(word, actionDoc, {
					subtitle: actionDoc.group ? `${actionDoc.group} Action` : undefined,
				})
				return new vscode.Hover(markdown, wordRange)
			}

			// Check for operators (like @rx, @beginsWith, etc.)
			const operatorMatch = lineText.match(/@([a-zA-Z_]+)/)
			if (operatorMatch && operatorMatch[1] === word) {
				const doc = documentation.operators[word]
				if (doc) {
					const markdown = createHoverMarkdown(`@${word}`, doc)
					return new vscode.Hover(markdown, wordRange)
				}
			}

			// Check for variables (ARGS, REQUEST_URI, etc.)
			const doc = documentation.variables[word]
			if (doc) {
				const markdown = createHoverMarkdown(word, doc)
				return new vscode.Hover(markdown, wordRange)
			}

			return undefined
		},
	})

	context.subscriptions.push(hoverProvider)
}

export function deactivate() {
	// Clean up if needed
}
