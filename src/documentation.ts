export interface DocEntry {
	description: string
	syntax?: string
	example?: string
	whenToUse?: string
	group?: string
	relatedActions?: string[]
}

interface Documentation {
	directives: { [key: string]: DocEntry }
	ctlActions: { [key: string]: DocEntry }
	actions: { [key: string]: DocEntry }
	operators: { [key: string]: DocEntry }
	variables: { [key: string]: DocEntry }
}

export const documentation: Documentation = {
	directives: {
		SecRule: {
			description: 'Creates a rule that will analyze the selected variables using the selected operator.',
			syntax: 'SecRule VARIABLES OPERATOR [ACTIONS]',
			example: 'SecRule ARGS "@rx attack" "id:1,phase:2,deny"',
			whenToUse: 'Creating detection and blocking rules based on patterns in request/response data.',
		},
		SecAction: {
			description: 'Unconditionally processes the action list it is given.',
			syntax: 'SecAction "ACTIONS"',
			example: 'SecAction "id:1,phase:1,log,pass"',
			whenToUse: 'Setting variables, initializing collections, or performing actions without matching conditions (e.g., setting up anomaly scoring, initializing IP tracking).',
		},
		SecMarker: {
			description: 'Adds a fixed-position mark that can be used as a target for skipAfter action. Markers are not processed by ModSecurity, they are simply placeholders.',
			syntax: 'SecMarker MARKER_NAME',
			example: 'SecMarker BEGIN_XSS_CHECKS',
			whenToUse: 'Creating jump targets for skipAfter flow control (e.g., skipping entire rule sections based on conditions).',
		},
		SecRuleUpdateActionById: {
			description: 'Updates the action list of the specified rule. This directive will overwrite the action list but cannot change the ID or phase.',
			syntax: 'SecRuleUpdateActionById RULEID ACTIONLIST',
			example: 'SecRuleUpdateActionById 12345 "deny,status:403"',
			whenToUse: 'Modifying how a third-party rule blocks without editing the original file (e.g., changing deny to block, or updating the status code).',
		},
		SecRuleUpdateTargetById: {
			description: 'Updates the target (variable) list of the specified rule.',
			syntax: 'SecRuleUpdateTargetById RULEID TARGET1[,TARGET2,TARGET3]',
			example: 'SecRuleUpdateTargetById 12345 "!ARGS:foo"',
			whenToUse: 'Implementing exceptions by excluding specific parameters from inspection (e.g., exclude ARGS:editor_content from XSS rules).',
		},
		SecRuleUpdateTargetByMsg: {
			description: 'Updates the target (variable) list of the specified rule(s) by rule message.',
			syntax: 'SecRuleUpdateTargetByMsg TEXT TARGET1[,TARGET2,TARGET3]',
			example: 'SecRuleUpdateTargetByMsg "Cross-site Scripting (XSS) Attack" "!ARGS:foo"',
			whenToUse: 'When you need to exclude a parameter from multiple rules that share the same message text.',
		},
		SecRuleUpdateTargetByTag: {
			description: 'Updates the target (variable) list of the specified rule(s) by rule tag.',
			syntax: 'SecRuleUpdateTargetByTag TEXT TARGET1[,TARGET2,TARGET3]',
			example: 'SecRuleUpdateTargetByTag "WEB_ATTACK/XSS" "!ARGS:foo"',
			whenToUse: 'When you need to exclude a parameter from all rules with a specific tag (e.g., all OWASP CRS XSS rules).',
		},
		SecRuleRemoveById: {
			description: 'Removes the matching rules from the current configuration context. This directive supports multiple rule IDs separated by spaces.',
			syntax: 'SecRuleRemoveById RULEID1 [RULEID2] [RULEID3]',
			example: 'SecRuleRemoveById 12345',
			whenToUse: 'Disabling specific third-party rules that cause false positives in your application.',
		},
		SecRuleRemoveByMsg: {
			description: 'Removes the matching rules from the current configuration context by message. In v3, matching is by case-sensitive string equality (not regex).',
			syntax: 'SecRuleRemoveByMsg REGEX',
			example: 'SecRuleRemoveByMsg "Cross-site Scripting"',
			whenToUse: 'Disabling all rules with a specific message text (useful when multiple rules share the same message).',
		},
		SecRuleRemoveByTag: {
			description: 'Removes the matching rules from the current configuration context by tag. In v3, matching is by case-sensitive string equality (not regex).',
			syntax: 'SecRuleRemoveByTag TAGNAME',
			example: 'SecRuleRemoveByTag "WEB_ATTACK/XSS"',
			whenToUse: 'Disabling entire categories of rules (e.g., disable all XSS rules for your application).',
		},
		SecDefaultAction: {
			description: 'Defines the default list of actions that will be used when rules do not explicitly specify any. Must appear before the rules to which it is applied.',
			syntax: 'SecDefaultAction "ACTIONS"',
			example: 'SecDefaultAction "phase:2,log,deny,status:403"',
			whenToUse: 'Setting baseline behavior for all rules in a phase (e.g., default to blocking with status 403, or default to detection-only).',
		},
		SecRuleEngine: {
			description: 'Configures the rules engine. DetectionOnly runs rules but does not execute disruptive actions.',
			syntax: 'SecRuleEngine On|Off|DetectionOnly',
			example: 'SecRuleEngine On',
			whenToUse: 'Set to DetectionOnly for testing rules without blocking traffic, Off to completely disable ModSecurity, or On for active protection.',
		},
		SecRequestBodyAccess: {
			description: 'Configures whether request bodies will be buffered and processed by ModSecurity. Must be On for inspection of POST payloads.',
			syntax: 'SecRequestBodyAccess On|Off',
			example: 'SecRequestBodyAccess On',
			whenToUse: 'Enable this when you need to inspect POST data, file uploads, or any request body content.',
		},
		SecResponseBodyAccess: {
			description: 'Configures whether response bodies will be buffered and processed by ModSecurity.',
			syntax: 'SecResponseBodyAccess On|Off',
			example: 'SecResponseBodyAccess On',
			whenToUse: 'Enable this for data leakage prevention (detecting credit cards, SSNs, or sensitive data in responses).',
		},
		SecAuditEngine: {
			description: 'Configures the audit engine. RelevantOnly will only log transactions that have triggered a rule with log action.',
			syntax: 'SecAuditEngine On|Off|RelevantOnly',
			example: 'SecAuditEngine RelevantOnly',
			whenToUse: 'Set to RelevantOnly to log only attacks, On to log all traffic (high disk usage), or Off to disable audit logging.',
		},
		SecAuditLog: {
			description: 'Defines the path to the main audit log file. Must be writable by the web server process.',
			syntax: 'SecAuditLog /path/to/audit.log',
			example: 'SecAuditLog /var/log/modsec_audit.log',
			whenToUse: 'Required when SecAuditEngine is enabled to specify where audit logs should be written.',
		},
	},

	ctlActions: {
		ruleRemoveTargetById: {
			description:
				"Removes specific targets (variables) from a rule at runtime. When removing targets, you don't need to use the ! character before the target list.",
			syntax: 'ctl:ruleRemoveTargetById=RULEID;TARGET',
			example:
				'SecRule REQUEST_URI "@beginsWith /index.php" "phase:1,t:none,pass,nolog,ctl:ruleRemoveTargetById=981260;ARGS:user"',
			whenToUse: 'Dynamically whitelisting specific parameters for particular rules based on request context (e.g., excluding a safe parameter from SQL injection checks on a specific page).',
		},
		ruleRemoveTargetByMsg: {
			description:
				"Removes specific targets (variables) from rules matched by message. When removing targets, you don't need to use the ! character before the target list.",
			syntax: 'ctl:ruleRemoveTargetByMsg=MESSAGE;TARGET',
			example: 'ctl:ruleRemoveTargetByMsg=XSS Attack;ARGS:safe_param',
			whenToUse: 'Not supported in ModSecurity v3.',
		},
		ruleRemoveTargetByTag: {
			description:
				"Removes specific targets (variables) from rules matched by tag. When removing targets, you don't need to use the ! character before the target list.",
			syntax: 'ctl:ruleRemoveTargetByTag=TAG;TARGET',
			example: 'ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:safe_param',
			whenToUse: 'Excluding parameters from entire rule sets based on tags (e.g., exclude a parameter from all OWASP CRS rules).',
		},
		ruleRemoveById: {
			description:
				"Disables a specific rule at runtime. Place this before the rule you want to disable, since it's triggered at runtime.",
			syntax: 'ctl:ruleRemoveById=RULEID',
			example: 'ctl:ruleRemoveById=12345',
			whenToUse: 'Conditionally disabling rules based on request characteristics (e.g., disable a rule only for authenticated users).',
		},
		ruleRemoveByTag: {
			description: 'Disables all rules with a matching tag at runtime.',
			syntax: 'ctl:ruleRemoveByTag=TAG',
			example: 'ctl:ruleRemoveByTag=OWASP_CRS/WEB_ATTACK/XSS',
			whenToUse: 'Conditionally disabling entire categories of rules (e.g., disable all XSS checks for a specific URL).',
		},
		requestBodyProcessor: {
			description: 'Configures how ModSecurity should parse the request body for this transaction. Supported processors: URLENCODED (form data), MULTIPART (file uploads), XML, and JSON.',
			syntax: 'ctl:requestBodyProcessor=PROCESSOR',
			example: 'SecRule REQUEST_CONTENT_TYPE "^text/xml" "nolog,pass,id:106,ctl:requestBodyProcessor=XML"',
			whenToUse: 'When the Content-Type header indicates a specific format that requires special parsing (e.g., set to XML for SOAP requests, JSON for REST APIs).',
		},
		ruleEngine: {
			description: 'Changes the rule engine mode for the current transaction only.',
			syntax: 'ctl:ruleEngine=On|Off|DetectionOnly',
			example: 'ctl:ruleEngine=Off',
			whenToUse: 'Conditionally enabling/disabling rule processing (e.g., turn off the engine for trusted IPs or specific URLs).',
		},
		auditEngine: {
			description: 'Changes the audit logging mode for the current transaction only.',
			syntax: 'ctl:auditEngine=On|Off|RelevantOnly',
			example: 'ctl:auditEngine=On',
			whenToUse: "Forcing audit logging for specific transactions, even if they don't trigger rules.",
		},
		auditLogParts: {
			description: 'Specifies which parts of the transaction to include in the audit log. Use + to add parts (e.g., +E for response body), or - to remove parts. Common parts: A (headers), B (request body), E (response body).',
			syntax: 'ctl:auditLogParts=+/-PARTS',
			example: 'ctl:auditLogParts=+E',
			whenToUse: 'When you need to include response bodies in audit logs for specific transactions (e.g., +E for data leakage investigation), or reduce log size by excluding parts.',
		},
	},

	actions: {
		id: {
			description: "Assigns a unique, numeric ID to this rule or chain. Required for SecRule and SecAction. The ID is used for logging, rule updates (SecRuleUpdateTargetById), and rule removal (ctl:ruleRemoveById). IDs don't affect execution order.",
			group: 'Meta-data',
			syntax: 'id:NUMBER',
			example: 'SecRule ARGS "@rx attack" "id:12345,deny"',
			whenToUse: 'Every rule needs a unique ID. Use reserved ranges for different purposes (e.g., 1-99,999 for local rules, 900,000+ for CRS rules).',
		},
		phase: {
			description: 'Specifies when this rule should execute during request/response processing.',
			group: 'Meta-data',
			syntax: 'phase:NUMBER (1-5) or phase:request|response|logging',
			example: 'phase:2',
			whenToUse: 'Choose the appropriate phase for your rule:\n\n• **Phase 1** (Request Headers) - Early detection based on URI, method, headers. Use for blocking known bad IPs or user agents.\n\n• **Phase 2** (Request Body) - Inspect POST data, file uploads, JSON/XML payloads. Most attack detection happens here.\n\n• **Phase 3** (Response Headers) - Inspect response headers before the body is read.\n\n• **Phase 4** (Response Body) - Check for data leakage (credit cards, SSNs, error messages).\n\n• **Phase 5** (Logging) - Post-processing, correlation, cannot block requests.',
		},
		msg: {
			description: 'Assigns a custom message to the rule or chain. The message will be logged when the rule triggers.',
			group: 'Meta-data',
			syntax: 'msg:"MESSAGE TEXT"',
			example: 'msg:"SQL Injection Attack Detected"',
			whenToUse: 'Providing a clear description of what the rule detected for log analysis and incident response.',
		},
		severity: {
			description: 'Assigns a severity level to a rule. Lower numbers indicate higher severity (0=EMERGENCY, 2=CRITICAL, 4=WARNING, etc.).',
			group: 'Meta-data',
			syntax: 'severity:LEVEL (0-7 or EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG)',
			example: 'severity:CRITICAL',
			whenToUse: 'Classifying the importance of rule matches for alerting, filtering, and anomaly scoring.',
		},
		log: {
			description: 'Logs this rule match to the error and audit logs.',
			group: 'Non-disruptive',
			syntax: 'log',
			example: 'log',
			whenToUse: 'Recording rule matches for monitoring and analysis. Combine with pass for non-blocking logging.',
			relatedActions: ['nolog', 'auditlog', 'noauditlog'],
		},
		nolog: {
			description: 'Prevents rule matches from appearing in the error and audit logs.',
			group: 'Non-disruptive',
			syntax: 'nolog',
			example: 'nolog',
			whenToUse: 'For rules that perform flow control or set variables without indicating an attack (e.g., whitelisting rules with pass).',
			relatedActions: ['log', 'auditlog', 'noauditlog'],
		},
		deny: {
			description: 'Stops rule processing and intercepts the transaction with the specified status code.',
			group: 'Disruptive',
			syntax: 'deny',
			example: 'SecRule ARGS "@rx attack" "id:1,deny,status:403"',
			whenToUse: 'Blocks the request immediately. Default status code is 403 unless specified with status:XXX.',
			relatedActions: ['allow', 'block', 'pass', 'drop', 'redirect'],
		},
		allow: {
			description: 'Stops rule processing and allows the transaction to proceed (whitelist action).',
			group: 'Disruptive',
			syntax: 'allow',
			example: 'allow',
			whenToUse: 'Bypasses all remaining rules in the current phase and all subsequent phases. Use for trusted content.',
			relatedActions: ['deny', 'block', 'pass', 'drop', 'redirect'],
		},
		block: {
			description: 'Performs the disruptive action defined by SecDefaultAction.',
			group: 'Disruptive',
			syntax: 'block',
			example: 'block',
			whenToUse: 'More flexible than deny - allows you to change the blocking behavior globally via SecDefaultAction instead of editing each rule.',
			relatedActions: ['deny', 'allow', 'pass', 'drop', 'redirect'],
		},
		pass: {
			description: 'Continues processing with the next rule even when this rule matches (non-blocking).',
			group: 'Disruptive',
			syntax: 'pass',
			example: 'pass',
			whenToUse: 'When you want to log, set variables, whitelist parameters (ctl:ruleRemoveTargetById), or perform other setup actions without blocking the request.',
			relatedActions: ['deny', 'allow', 'block', 'drop', 'redirect'],
		},
		drop: {
			description: 'In ModSecurity v3, this currently functions the same as deny.',
			group: 'Disruptive',
			syntax: 'drop',
			example: 'drop',
			whenToUse: 'Behavior differs from v2 where it would drop the TCP connection.',
			relatedActions: ['deny', 'allow', 'block', 'pass', 'redirect'],
		},
		redirect: {
			description: 'Redirects the transaction to another URL. Sends a 302 (Moved Temporarily) response and stops rule processing.',
			group: 'Disruptive',
			syntax: 'redirect:URL',
			example: 'redirect:http://www.example.com/error.html',
			whenToUse: 'When you want to send attackers or suspicious requests to a different page (e.g., redirect to a warning page or honeypot).',
			relatedActions: ['deny', 'allow', 'block', 'pass', 'drop'],
		},
		status: {
			description: 'Specifies the response status code to use with deny or redirect actions. Common values: 403 (Forbidden), 404 (Not Found), 500 (Internal Server Error).',
			group: 'Non-disruptive',
			syntax: 'status:NUMBER',
			example: 'status:403',
			whenToUse: 'When you want to return a specific HTTP status code instead of the default 403 (e.g., return 404 to hide protected resources).',
		},
		chain: {
			description: 'Chains the current rule with the rule that immediately follows it. All rules in a chain must match for the disruptive action to trigger.',
			group: 'Non-disruptive',
			syntax: 'chain',
			example: 'chain',
			whenToUse: 'When you need multiple conditions to all be true (logical AND), like checking both request method AND a specific parameter value.',
		},
		skip: {
			description: 'Skips one or more rules in the chain on a successful match. Can only be used in chained rules.',
			group: 'Non-disruptive',
			syntax: 'skip:NUMBER',
			example: 'skip:2',
			whenToUse: 'Creating conditional logic in chains where some checks should be skipped based on earlier results.',
		},
		skipAfter: {
			description: 'Skips all rules until a rule with the given marker is found.',
			group: 'Non-disruptive',
			syntax: 'skipAfter:MARKER',
			example: 'skipAfter:END_CHECKS',
			whenToUse: 'Flow control and conditional rule execution (e.g., skip all XSS checks if the content-type is JSON, or skip checks for whitelisted IPs).',
		},
		setvar: {
			description: 'Creates, removes, or updates a variable.',
			group: 'Non-disruptive',
			syntax: 'setvar:NAME=VALUE or setvar:!NAME or setvar:NAME',
			example: 'setvar:tx.score=+5',
			whenToUse: 'Implementing anomaly scoring (incrementing scores), tracking state across rules, or storing data for use in later phases.',
		},
		t: {
			description: 'Applies a transformation function to normalize input data before pattern matching. Chain multiple transformations to apply them in order. Use t:none to clear inherited transformations. Common: lowercase, urlDecode, removeWhitespace, htmlEntityDecode.',
			group: 'Non-disruptive',
			syntax: 't:FUNCTION',
			example: 't:lowercase,t:urlDecode',
			whenToUse: 'Normalizing input to detect evasion attempts (e.g., use urlDecode to catch %73%71%6c encoded "sql", or lowercase to catch "SQL" and "sql").',
		},
		ctl: {
			description: 'Changes ModSecurity configuration on a transient, per-transaction basis. Any changes made using this action will affect only the current transaction.',
			group: 'Non-disruptive',
			syntax: 'ctl:OPTION=VALUE',
			example: 'ctl:ruleRemoveTargetById=981260;ARGS:user',
			whenToUse: 'Dynamically adjusting rule behavior based on request context (e.g., disable specific checks for admin users, or remove targets for known safe parameters).',
		},
		tag: {
			description: 'Assigns a tag (category) to a rule. Multiple tags can be specified for a single rule.',
			group: 'Meta-data',
			syntax: 'tag:TAG_NAME',
			example: 'tag:OWASP_CRS/WEB_ATTACK/XSS',
			whenToUse: 'Organizing rules into categories for easier management, filtering logs, or bulk operations (e.g., disable all "OWASP_CRS" tagged rules).',
		},
		ver: {
			description: 'Specifies the rule set version.',
			group: 'Meta-data',
			syntax: 'ver:VERSION',
			example: 'ver:1.2.3',
			whenToUse: 'Tracking which version of a rule set is deployed for troubleshooting and compliance.',
		},
		rev: {
			description: 'Specifies the rule revision.',
			group: 'Meta-data',
			syntax: 'rev:REVISION',
			example: 'rev:2',
			whenToUse: 'Tracking individual rule changes over time (increment when you modify a rule).',
		},
		maturity: {
			description: 'Specifies the rule maturity level. Higher numbers (1-9) indicate more mature/tested rules.',
			group: 'Meta-data',
			syntax: 'maturity:LEVEL (1-9)',
			example: 'maturity:8',
			whenToUse: 'Filtering rules by maturity level to enable only well-tested rules in production (e.g., only enable maturity 8+ rules).',
		},
		accuracy: {
			description: 'Specifies the rule accuracy level. Higher numbers (1-9) indicate lower false positive rates.',
			group: 'Meta-data',
			syntax: 'accuracy:LEVEL (1-9)',
			example: 'accuracy:9',
			whenToUse: 'Filtering rules by accuracy to reduce false positives (e.g., only enable accuracy 7+ rules to minimize noise).',
		},
		logdata: {
			description: 'Specifies additional data to be logged with a rule match. Supports variable expansion.',
			group: 'Non-disruptive',
			syntax: 'logdata:"DATA"',
			example: 'logdata:"Matched Data: %{MATCHED_VAR}"',
			whenToUse: 'Including dynamic context in logs for debugging (e.g., log the exact matched value, request ID, or user session).',
		},
		capture: {
			description: 'Copies captured substrings from the regular expression to the transaction collection. Captured data is available in TX.0-TX.9 variables.',
			group: 'Non-disruptive',
			syntax: 'capture',
			example: 'capture',
			whenToUse: 'When you need to extract and use parts of a matched pattern in later rules or logging (e.g., extract a session ID from a malicious request).',
		},
		multiMatch: {
			description: 'Forces the rule to match on all occurrences of a variable, not just the first.',
			group: 'Non-disruptive',
			syntax: 'multiMatch',
			example: 'multiMatch',
			whenToUse: 'Thorough inspection of all instances when dealing with collections like ARGS (e.g., check all parameters, not just the first match).',
		},
		exec: {
			description: 'Executes an external script supplied as parameter. ModSecurity v3 currently only supports Lua scripts.',
			group: 'Non-disruptive',
			syntax: 'exec:/path/to/script.lua',
			example: 'exec:/usr/local/apache/conf/exec.lua',
			whenToUse: 'When built-in ModSecurity features are insufficient and you need custom logic (e.g., complex validation, external API calls, or custom scoring).',
		},
		auditlog: {
			description: 'Marks the transaction to be logged to the audit log. Transaction will be logged regardless of audit engine settings.',
			group: 'Non-disruptive',
			syntax: 'auditlog',
			example: 'auditlog',
			whenToUse: 'Forcing specific transactions to be logged even when SecAuditEngine is Off or RelevantOnly (e.g., always log admin panel access).',
		},
		noauditlog: {
			description: 'Prevents the transaction from being logged to the audit log.',
			group: 'Non-disruptive',
			syntax: 'noauditlog',
			example: 'noauditlog',
			whenToUse: 'Reducing audit log noise for benign detections or high-volume endpoints (e.g., health checks, monitoring probes).',
		},
	},

	operators: {
		rx: {
			description: 'Regular expression match. This is the default operator if none is specified. Uses PCRE (Perl Compatible Regular Expressions) syntax.',
			syntax: '"@rx PATTERN"',
			example: 'SecRule ARGS "@rx <script" "id:1,deny"',
			whenToUse: 'When you need pattern matching with wildcards, character classes, or complex logic (e.g., detecting SQL injection patterns, XSS tags).',
		},
		pm: {
			description: 'Parallel matching operator that performs case-insensitive matching of multiple patterns at once. Much faster than multiple rx operators for simple string matching.',
			syntax: '"@pm PATTERN1 PATTERN2 ..."',
			example: 'SecRule ARGS "@pm attack hack exploit" "id:1,deny"',
			whenToUse: 'When you need to match against a list of known strings efficiently (e.g., checking for known malicious keywords, file extensions).',
		},
		eq: {
			description: 'Performs numerical comparison (equal to). Often used with variable counting (& prefix).',
			syntax: '"@eq NUMBER"',
			example: 'SecRule &ARGS "@eq 0" "id:1,deny"',
			whenToUse: 'Checking exact counts (e.g., deny if no arguments provided, or if a variable equals a specific value).',
		},
		ge: {
			description: 'Performs numerical comparison (greater than or equal to).',
			syntax: '"@ge NUMBER"',
			example: 'SecRule REQUEST_BODY_LENGTH "@ge 1000000" "id:1,deny"',
			whenToUse: 'Enforcing maximum sizes or thresholds (e.g., block requests with bodies over 1MB, or anomaly scores >= 10).',
		},
		gt: {
			description: 'Performs numerical comparison (greater than).',
			syntax: '"@gt NUMBER"',
			example: 'SecRule TX:anomaly_score "@gt 5" "id:1,deny"',
			whenToUse: 'Implementing anomaly scoring thresholds (e.g., block if total score exceeds 5) or validation rules.',
		},
		le: {
			description: 'Performs numerical comparison (less than or equal to).',
			syntax: '"@le NUMBER"',
			example: 'SecRule ARGS:age "@le 0" "id:1,deny"',
			whenToUse: 'Enforcing minimum values or validating input ranges (e.g., reject age <= 0, or counts within limits).',
		},
		lt: {
			description: 'Performs numerical comparison (less than).',
			syntax: '"@lt NUMBER"',
			example: 'SecRule ARGS:quantity "@lt 1" "id:1,deny"',
			whenToUse: 'Validating minimum values (e.g., reject quantity < 1, or check if variable counts are too low).',
		},
		contains: {
			description: 'String match: checks if the target string contains the parameter string. Case-sensitive unless used with t:lowercase.',
			syntax: '"@contains STRING"',
			example: 'SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:1,deny"',
			whenToUse: 'Simple substring detection faster than regex (e.g., checking if User-Agent contains "bot", or if a parameter contains "script").',
		},
		beginsWith: {
			description: 'String match: checks if the target string begins with the parameter string.',
			syntax: '"@beginsWith STRING"',
			example: 'SecRule REQUEST_URI "@beginsWith /admin" "id:1,deny"',
			whenToUse: 'Path-based matching for protecting specific URL prefixes (e.g., block access to /admin, /api/internal).',
		},
		endsWith: {
			description: 'String match: checks if the target string ends with the parameter string.',
			syntax: '"@endsWith STRING"',
			example: 'SecRule REQUEST_FILENAME "@endsWith .php" "id:1,deny"',
			whenToUse: 'File extension checks (e.g., block .exe uploads, or allow only .jpg images).',
		},
		streq: {
			description: 'String match: checks if the target string equals the parameter string. Case-sensitive exact match.',
			syntax: '"@streq STRING"',
			example: 'SecRule REQUEST_METHOD "@streq POST" "id:1,pass"',
			whenToUse: 'Exact string matching for whitelisting or validation (e.g., check if method is exactly "POST", or if a header equals a specific value).',
		},
		within: {
			description: 'String match: checks if the target string is found within the parameter string (reverse of contains).',
			syntax: '"@within STRING"',
			example: 'SecRule REQUEST_METHOD "@within GET POST HEAD" "id:1,pass"',
			whenToUse: 'Whitelisting by checking if a value is in an allowed list (e.g., allow only GET/POST/HEAD methods).',
		},
		detectSQLi: {
			description: 'Detects SQL injection attacks using libinjection. Uses advanced detection with machine learning techniques.',
			syntax: '"@detectSQLi"',
			example: 'SecRule ARGS "@detectSQLi" "id:1,deny,msg:\'SQL Injection\'"',
			whenToUse: 'High-accuracy SQL injection detection as a supplement to regex-based rules (lower false positives than pattern matching).',
		},
		detectXSS: {
			description: 'Detects XSS attacks using libinjection. Uses advanced detection with machine learning techniques.',
			syntax: '"@detectXSS"',
			example: 'SecRule ARGS "@detectXSS" "id:1,deny,msg:\'XSS Attack\'"',
			whenToUse: 'High-accuracy XSS detection as a supplement to regex-based rules (catches obfuscated and novel XSS vectors).',
		},
		validateByteRange: {
			description: 'Validates that all bytes in the input fall within the specified range.',
			syntax: '"@validateByteRange RANGE1[,RANGE2,...]"',
			example: 'SecRule ARGS "@validateByteRange 32-126" "id:1,deny"',
			whenToUse: 'Detecting binary data or control characters in text fields (e.g., reject null bytes, or enforce printable ASCII only).',
		},
		validateUrlEncoding: {
			description: 'Validates the URL encoding in the input. Detects invalid URL encoding that could be used for evasion.',
			syntax: '"@validateUrlEncoding"',
			example: 'SecRule REQUEST_URI "@validateUrlEncoding" "id:1,deny"',
			whenToUse: 'Preventing evasion attempts using malformed URL encoding (e.g., %ZZ or %1 instead of valid %XX sequences).',
		},
		validateUtf8Encoding: {
			description: 'Validates the UTF-8 encoding in the input.',
			syntax: '"@validateUtf8Encoding"',
			example: 'SecRule ARGS "@validateUtf8Encoding" "id:1,deny"',
			whenToUse: 'Preventing UTF-8 encoding attacks and malformed Unicode sequences that could bypass filters or cause parser issues.',
		},
		ipMatch: {
			description: 'Performs a fast IP address match. Supports individual IPs, ranges, and CIDR notation.',
			syntax: '"@ipMatch IP1[,IP2,...]"',
			example: 'SecRule REMOTE_ADDR "@ipMatch 192.168.1.0/24" "id:1,deny"',
			whenToUse: 'Blocking or allowing specific IPs or IP ranges (e.g., blacklist known attackers, whitelist internal networks).',
		},
		ipMatchFromFile: {
			description: 'Performs IP address match using IPs from a file. File should contain one IP/range per line.',
			syntax: '"@ipMatchFromFile /path/to/file"',
			example: 'SecRule REMOTE_ADDR "@ipMatchFromFile /etc/modsec/blacklist.txt" "id:1,deny"',
			whenToUse: 'Managing large IP blacklists or whitelists externally (easier to update without editing rules).',
		},
		geoLookup: {
			description: 'Performs geolocation lookup on the IP address. Requires GeoIP database configuration.',
			syntax: '"@geoLookup"',
			example: 'SecRule REMOTE_ADDR "@geoLookup" "chain,id:1"\nSecRule GEO:COUNTRY_CODE "@streq CN" "deny"',
			whenToUse: 'Blocking or allowing traffic based on geographic location (e.g., block countries with high fraud rates, or restrict admin access to specific countries).',
		},
		rbl: {
			description: 'Checks the input against a DNS-based blacklist (RBL).',
			syntax: '"@rbl DNSBL_DOMAIN"',
			example: 'SecRule REMOTE_ADDR "@rbl zen.spamhaus.org" "id:1,deny"',
			whenToUse: 'Blocking known spam/malware sources using real-time blacklists (e.g., Spamhaus, TorProject exit nodes).',
		},
		verifyCC: {
			description: 'Detects and validates credit card numbers. Uses Luhn algorithm for validation.',
			syntax: '"@verifyCC CARD_TYPES"',
			example: 'SecRule ARGS "@verifyCC VISA MASTERCARD" "id:1,deny,msg:\'Credit Card Found\'"',
			whenToUse: 'Data leakage prevention in response bodies or detecting credit card numbers in request parameters (PCI compliance).',
		},
		verifyCPF: {
			description: 'Validates Brazilian CPF numbers (Brazilian tax IDs).',
			syntax: '"@verifyCPF"',
			example: 'SecRule ARGS "@verifyCPF" "id:1,deny"',
			whenToUse: 'Data leakage prevention for Brazilian applications to detect exposed CPF numbers in responses or requests.',
		},
		verifySSN: {
			description: 'Validates US Social Security Numbers.',
			syntax: '"@verifySSN"',
			example: 'SecRule ARGS "@verifySSN" "id:1,deny,msg:\'SSN Found\'"',
			whenToUse: 'Data leakage prevention to detect exposed Social Security Numbers in responses or request parameters.',
		},
	},

	variables: {
		ARGS: {
			description: 'Contains all request parameters (query string and POST data combined).\n\nSupports selectors:\n\n- `ARGS:name` - Select specific parameter\n- `ARGS:/regex/` - Pattern match with regex\n- `!ARGS:name` - Exclude specific parameter\n- `&ARGS` - Count parameters\n\n**Note:** Regex selectors (:/pattern/) do not work in `ctl:ruleRemoveTargetById` or `SecRuleUpdateTargetById` - only exact names work there ([GitHub issue #717](https://github.com/owasp-modsecurity/ModSecurity/issues/717)).',
			example: 'SecRule ARGS "@rx attack" "id:1,deny"',
			whenToUse: 'Inspecting all user-supplied parameters in a single rule. Use `ARGS:name` for specific parameters, `ARGS:/^prefix_/` for pattern matching, or `!ARGS:csrf` to exclude specific params.',
		},
		ARGS_GET: {
			description: 'Contains all query string (GET) parameters. Supports the same selectors as ARGS (`:name`, `:/regex/`, `!:name`, `&`).',
			example: 'SecRule ARGS_GET "@rx attack" "id:1,deny"',
			whenToUse: 'When you specifically need to inspect query string parameters separately from POST data.',
		},
		ARGS_POST: {
			description: 'Contains all POST parameters. Supports the same selectors as ARGS (`:name`, `:/regex/`, `!:name`, `&`).',
			example: 'SecRule ARGS_POST "@rx attack" "id:1,deny"',
			whenToUse: 'When you specifically need to inspect POST body parameters separately from query strings.',
		},
		ARGS_NAMES: {
			description: 'Contains all parameter names (both GET and POST). Useful for detecting suspicious parameter names. Supports the same selectors as ARGS.',
			example: 'SecRule ARGS_NAMES "@rx (cmd|exec)" "id:1,deny"',
			whenToUse: 'Detecting malicious patterns in parameter names themselves (e.g., parameters called "cmd", "eval", or "__proto__").',
		},
		REQUEST_URI: {
			description: 'Contains the full request URI (with query string, but normalized).',
			example: 'SecRule REQUEST_URI "@contains /admin" "id:1,deny"',
			whenToUse: 'Path-based detection after normalization (e.g., blocking admin paths, detecting directory traversal patterns).',
		},
		REQUEST_URI_RAW: {
			description: 'Contains the full request URI exactly as it was received (not normalized).',
			example: 'SecRule REQUEST_URI_RAW "@contains %00" "id:1,deny"',
			whenToUse: 'Detecting evasion attempts that rely on encoding or obfuscation (e.g., null bytes, double encoding).',
		},
		REQUEST_FILENAME: {
			description: 'Contains the file path portion of the request URI (no query string).',
			example: 'SecRule REQUEST_FILENAME "@endsWith .php" "id:1,pass"',
			whenToUse: 'File extension checks or path-based rules without query string interference.',
		},
		REQUEST_METHOD: {
			description: 'Contains the request method (GET, POST, etc.).',
			example: 'SecRule REQUEST_METHOD "!@within GET POST HEAD" "id:1,deny"',
			whenToUse: 'Restricting allowed HTTP methods or applying method-specific rules.',
		},
		REQUEST_PROTOCOL: {
			description: 'Contains the request protocol (HTTP/1.0, HTTP/1.1, etc.).',
			example: 'SecRule REQUEST_PROTOCOL "!@streq HTTP/1.1" "id:1,log"',
			whenToUse: 'Detecting old protocol versions or protocol anomalies.',
		},
		REQUEST_HEADERS: {
			description: 'Contains all request headers. Supports selectors like `REQUEST_HEADERS:name` or `REQUEST_HEADERS:/regex/`.',
			example: 'SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:1,deny"',
			whenToUse: 'Inspecting HTTP headers for attacks or anomalies (e.g., detecting malicious User-Agents, missing required headers, or header injection).',
		},
		REQUEST_HEADERS_NAMES: {
			description: 'Contains all request header names. Supports selectors.',
			example: 'SecRule REQUEST_HEADERS_NAMES "@rx ^X-" "id:1,log"',
			whenToUse: 'Detecting suspicious or unexpected header names (e.g., custom headers that might indicate probing or specific attack tools).',
		},
		REQUEST_COOKIES: {
			description: 'Contains all request cookies. Supports selectors like `REQUEST_COOKIES:name` or `REQUEST_COOKIES:/regex/`.',
			example: 'SecRule REQUEST_COOKIES:sessionid "@rx [^a-zA-Z0-9]" "id:1,deny"',
			whenToUse: 'Validating cookie values or detecting cookie-based attacks (e.g., session fixation, XSS in cookies).',
		},
		REQUEST_COOKIES_NAMES: {
			description: 'Contains all request cookie names. Supports selectors.',
			example: 'SecRule REQUEST_COOKIES_NAMES "@rx __" "id:1,log"',
			whenToUse: 'Detecting suspicious cookie names that might indicate framework-specific attacks or tracking mechanisms.',
		},
		REQUEST_BODY: {
			description: 'Contains the raw request body (POST data).',
			example: 'SecRule REQUEST_BODY "@contains malware" "id:1,deny"',
			whenToUse: 'Inspecting the entire POST body for patterns (less common than using ARGS since it includes raw format without parsing).',
		},
		RESPONSE_HEADERS: {
			description: 'Contains all response headers. Supports selectors like `RESPONSE_HEADERS:name` or `RESPONSE_HEADERS:/regex/`.',
			example: 'SecRule RESPONSE_HEADERS:Content-Type "@contains text/html" "id:1,pass"',
			whenToUse: 'Validating response headers or detecting information leakage in headers (e.g., server version disclosure).',
		},
		RESPONSE_BODY: {
			description: 'Contains the response body.',
			example: 'SecRule RESPONSE_BODY "@contains SSN:" "id:1,deny,msg:\'Data Leakage\'"',
			whenToUse: 'Data leakage prevention - detecting sensitive data in responses (credit cards, SSNs, API keys, SQL errors).',
		},
		RESPONSE_STATUS: {
			description: 'Contains the response status code.',
			example: 'SecRule RESPONSE_STATUS "@eq 500" "id:1,log,auditlog"',
			whenToUse: 'Logging or alerting on specific status codes (e.g., track 500 errors, detect 404 scanning).',
		},
		REMOTE_ADDR: {
			description: 'Contains the IP address of the remote client.',
			example: 'SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:1,deny"',
			whenToUse: 'IP-based access control, blacklisting, or whitelisting trusted networks.',
		},
		REMOTE_HOST: {
			description: 'Contains the hostname of the remote client (if available).',
			example: 'SecRule REMOTE_HOST "@endsWith .cn" "id:1,log"',
			whenToUse: 'Hostname-based filtering when reverse DNS is configured (less reliable than IP-based filtering).',
		},
		REMOTE_USER: {
			description: 'Contains the authenticated username (if HTTP authentication is used).',
			example: 'SecRule REMOTE_USER "@streq admin" "id:1,log"',
			whenToUse: 'Applying different rules based on authenticated user or logging specific user activity.',
		},
		TX: {
			description: 'Transaction collection - used for storing temporary data during transaction processing. Supports selectors like `TX:name`.',
			example: 'SecRule TX:anomaly_score "@gt 5" "id:1,deny"',
			whenToUse: 'Anomaly scoring, storing state between rules, or passing data between phases.',
		},
		MATCHED_VAR: {
			description: 'Contains the value of the variable that matched in the current rule.',
			example: 'SecRule ARGS "@rx attack" "id:1,deny,msg:\'Attack: %{MATCHED_VAR}\'"',
			whenToUse: 'Including the actual matched value in log messages or further rule logic.',
		},
		MATCHED_VAR_NAME: {
			description: 'Contains the name of the variable that matched in the current rule.',
			example: 'SecRule ARGS "@rx attack" "id:1,deny,msg:\'Attack in %{MATCHED_VAR_NAME}\'"',
			whenToUse: 'Including which specific parameter/header/variable matched in log messages.',
		},
		FILES: {
			description: 'Contains uploaded files (multipart/form-data). Supports selectors.',
			example: 'SecRule FILES "@rx malware" "id:1,deny"',
			whenToUse: 'Inspecting file upload content for malware signatures or malicious patterns.',
		},
		FILES_NAMES: {
			description: 'Contains the names of uploaded files. Supports selectors.',
			example: 'SecRule FILES_NAMES "@endsWith .exe" "id:1,deny"',
			whenToUse: 'Blocking specific file types by extension or detecting suspicious filenames.',
		},
		XML: {
			description: 'Contains parsed XML data (when requestBodyProcessor=XML is used). Supports XPath-like selectors.',
			example: 'SecRule XML://@username "@contains admin" "id:1,deny"',
			whenToUse: 'Inspecting XML/SOAP requests by accessing specific XML elements or attributes (e.g., validating XML structure, detecting XML injection).',
		},
		GEO: {
			description: 'Contains geolocation data after @geoLookup operator is used. Access fields like GEO:COUNTRY_CODE, GEO:COUNTRY_NAME, GEO:REGION, GEO:CITY.',
			example: 'SecRule GEO:COUNTRY_CODE "@streq CN" "id:1,deny"',
			whenToUse: 'Geographic access control after performing a @geoLookup (e.g., blocking specific countries, alerting on unusual locations).',
		},
		DURATION: {
			description: 'Contains the number of milliseconds elapsed since the beginning of the transaction.',
			example: 'SecRule DURATION "@gt 1000" "id:1,log,msg:\'Slow request\'"',
			whenToUse: 'Detecting slow requests that might indicate DoS attacks or application performance issues.',
		},
	},
}
