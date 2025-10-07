interface DocEntry {
	description: string
	syntax?: string
	example?: string
	note?: string
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
			note: 'This is the most commonly used directive in ModSecurity.',
		},
		SecAction: {
			description: 'Unconditionally processes the action list it is given.',
			syntax: 'SecAction "ACTIONS"',
			example: 'SecAction "id:1,phase:1,log,pass"',
			note: 'SecAction is useful for setting variables, initializing persistent collections, etc.',
		},
		SecMarker: {
			description: 'Adds a fixed-position mark that can be used as a target for skipAfter action.',
			syntax: 'SecMarker MARKER_NAME',
			example: 'SecMarker BEGIN_XSS_CHECKS',
			note: 'Markers are not processed by ModSecurity, they are simply placeholders.',
		},
		SecRuleUpdateActionById: {
			description: 'Updates the action list of the specified rule.',
			syntax: 'SecRuleUpdateActionById RULEID ACTIONLIST',
			example: 'SecRuleUpdateActionById 12345 "deny,status:403"',
			note: 'This directive will overwrite the action list of the specified rule. It cannot be used to change the ID or phase of a rule.',
		},
		SecRuleUpdateTargetById: {
			description: 'Updates the target (variable) list of the specified rule.',
			syntax: 'SecRuleUpdateTargetById RULEID TARGET1[,TARGET2,TARGET3]',
			example: 'SecRuleUpdateTargetById 12345 "!ARGS:foo"',
			note: 'Useful for implementing exceptions where you want to externally update a target list to exclude inspection of specific variable(s).',
		},
		SecRuleUpdateTargetByMsg: {
			description: 'Updates the target (variable) list of the specified rule(s) by rule message.',
			syntax: 'SecRuleUpdateTargetByMsg TEXT TARGET1[,TARGET2,TARGET3]',
			example: 'SecRuleUpdateTargetByMsg "Cross-site Scripting (XSS) Attack" "!ARGS:foo"',
			note: 'Useful for updating multiple rules that share the same message.',
		},
		SecRuleUpdateTargetByTag: {
			description: 'Updates the target (variable) list of the specified rule(s) by rule tag.',
			syntax: 'SecRuleUpdateTargetByTag TEXT TARGET1[,TARGET2,TARGET3]',
			example: 'SecRuleUpdateTargetByTag "WEB_ATTACK/XSS" "!ARGS:foo"',
			note: 'Useful for updating multiple rules that share the same tag.',
		},
		SecRuleRemoveById: {
			description: 'Removes the matching rules from the current configuration context.',
			syntax: 'SecRuleRemoveById RULEID1 [RULEID2] [RULEID3]',
			example: 'SecRuleRemoveById 12345',
			note: 'This directive supports multiple rule IDs separated by spaces.',
		},
		SecRuleRemoveByMsg: {
			description: 'Removes the matching rules from the current configuration context by message.',
			syntax: 'SecRuleRemoveByMsg REGEX',
			example: 'SecRuleRemoveByMsg "Cross-site Scripting"',
			note: 'Uses regular expressions to match rule messages.',
		},
		SecRuleRemoveByTag: {
			description: 'Removes the matching rules from the current configuration context by tag.',
			syntax: 'SecRuleRemoveByTag TAGNAME',
			example: 'SecRuleRemoveByTag "WEB_ATTACK/XSS"',
			note: 'Allows removing multiple rules that share a common tag.',
		},
		SecDefaultAction: {
			description: 'Defines the default list of actions that will be used when rules do not explicitly specify any.',
			syntax: 'SecDefaultAction "ACTIONS"',
			example: 'SecDefaultAction "phase:2,log,deny,status:403"',
			note: 'Must appear before the rules to which it is applied.',
		},
		SecRuleEngine: {
			description: 'Configures the rules engine.',
			syntax: 'SecRuleEngine On|Off|DetectionOnly',
			example: 'SecRuleEngine On',
			note: 'DetectionOnly runs rules but does not execute disruptive actions.',
		},
		SecRequestBodyAccess: {
			description: 'Configures whether request bodies will be buffered and processed by ModSecurity.',
			syntax: 'SecRequestBodyAccess On|Off',
			example: 'SecRequestBodyAccess On',
			note: 'Must be On for inspection of POST payloads.',
		},
		SecResponseBodyAccess: {
			description: 'Configures whether response bodies will be buffered and processed by ModSecurity.',
			syntax: 'SecResponseBodyAccess On|Off',
			example: 'SecResponseBodyAccess On',
			note: 'Response body inspection is required for data leakage prevention.',
		},
		SecAuditEngine: {
			description: 'Configures the audit engine.',
			syntax: 'SecAuditEngine On|Off|RelevantOnly',
			example: 'SecAuditEngine RelevantOnly',
			note: 'RelevantOnly will only log transactions that have triggered a rule with log action.',
		},
		SecAuditLog: {
			description: 'Defines the path to the main audit log file.',
			syntax: 'SecAuditLog /path/to/audit.log',
			example: 'SecAuditLog /var/log/modsec_audit.log',
			note: 'Must be writable by the web server process.',
		},
	},

	ctlActions: {
		ruleRemoveTargetById: {
			description:
				"Removes specific targets (variables) from a rule at runtime. When removing targets, you don't need to use the ! character before the target list.",
			syntax: 'ctl:ruleRemoveTargetById=RULEID;TARGET',
			example:
				'SecRule REQUEST_URI "@beginsWith /index.php" "phase:1,t:none,pass,nolog,ctl:ruleRemoveTargetById=981260;ARGS:user"',
			note: 'Use this to dynamically whitelist specific parameters for particular rules based on request context.',
		},
		ruleRemoveTargetByMsg: {
			description:
				"Removes specific targets (variables) from rules matched by message. When removing targets, you don't need to use the ! character before the target list.",
			syntax: 'ctl:ruleRemoveTargetByMsg=MESSAGE;TARGET',
			example: 'ctl:ruleRemoveTargetByMsg=XSS Attack;ARGS:safe_param',
			note: 'Not supported in ModSecurity v3.',
		},
		ruleRemoveTargetByTag: {
			description:
				"Removes specific targets (variables) from rules matched by tag. When removing targets, you don't need to use the ! character before the target list.",
			syntax: 'ctl:ruleRemoveTargetByTag=TAG;TARGET',
			example: 'ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:safe_param',
			note: 'Use this to exclude parameters from entire rule sets based on tags.',
		},
		ruleRemoveById: {
			description:
				"Disables a specific rule at runtime. Place this before the rule you want to disable, since it's triggered at runtime.",
			syntax: 'ctl:ruleRemoveById=RULEID',
			example: 'ctl:ruleRemoveById=12345',
			note: 'Use this to conditionally disable rules based on request characteristics (e.g., disable a rule only for authenticated users).',
		},
		ruleRemoveByTag: {
			description: 'Disables all rules with a matching tag at runtime.',
			syntax: 'ctl:ruleRemoveByTag=TAG',
			example: 'ctl:ruleRemoveByTag=OWASP_CRS/WEB_ATTACK/XSS',
			note: 'Use this to conditionally disable entire categories of rules (e.g., disable all XSS checks for a specific URL).',
		},
		requestBodyProcessor: {
			description: 'Configures how ModSecurity should parse the request body for this transaction.',
			syntax: 'ctl:requestBodyProcessor=PROCESSOR',
			example: 'SecRule REQUEST_CONTENT_TYPE "^text/xml" "nolog,pass,id:106,ctl:requestBodyProcessor=XML"',
			note: 'Supported processors: URLENCODED (form data), MULTIPART (file uploads), XML, and JSON.',
		},
		ruleEngine: {
			description: 'Changes the rule engine mode for the current transaction only.',
			syntax: 'ctl:ruleEngine=On|Off|DetectionOnly',
			example: 'ctl:ruleEngine=Off',
			note: 'Use this to conditionally enable/disable rule processing (e.g., turn off the engine for trusted IPs or specific URLs).',
		},
		auditEngine: {
			description: 'Changes the audit logging mode for the current transaction only.',
			syntax: 'ctl:auditEngine=On|Off|RelevantOnly',
			example: 'ctl:auditEngine=On',
			note: "Use this to force audit logging for specific transactions, even if they don't trigger rules.",
		},
		auditLogParts: {
			description: 'Specifies which parts of the transaction to include in the audit log.',
			syntax: 'ctl:auditLogParts=+/-PARTS',
			example: 'ctl:auditLogParts=+E',
			note: 'Use + to add parts (e.g., +E for response body), or - to remove parts. Common parts: A (headers), B (request body), E (response body).',
		},
	},

	actions: {
		id: {
			description: 'Assigns a unique, numeric ID to this rule or chain.',
			group: 'Meta-data',
			syntax: 'id:NUMBER',
			example: 'SecRule ARGS "@rx attack" "id:12345,deny"',
			note: "Required for SecRule and SecAction. The ID is used for logging, rule updates (SecRuleUpdateTargetById), and rule removal (ctl:ruleRemoveById). IDs don't affect execution order.",
		},
		phase: {
			description: 'Specifies when this rule should execute during request/response processing.',
			group: 'Meta-data',
			syntax: 'phase:NUMBER (1-5) or phase:request|response|logging',
			example: 'phase:2',
			note: 'Choose the appropriate phase for your rule:\n\n• **Phase 1** (Request Headers) - Early detection based on URI, method, headers. Use for blocking known bad IPs or user agents.\n\n• **Phase 2** (Request Body) - Inspect POST data, file uploads, JSON/XML payloads. Most attack detection happens here.\n\n• **Phase 3** (Response Headers) - Inspect response headers before the body is read.\n\n• **Phase 4** (Response Body) - Check for data leakage (credit cards, SSNs, error messages).\n\n• **Phase 5** (Logging) - Post-processing, correlation, cannot block requests.',
		},
		msg: {
			description: 'Assigns a custom message to the rule or chain.',
			group: 'Meta-data',
			syntax: 'msg:"MESSAGE TEXT"',
			example: 'msg:"SQL Injection Attack Detected"',
			note: 'The message will be logged when the rule triggers.',
		},
		severity: {
			description: 'Assigns a severity level to a rule.',
			group: 'Meta-data',
			syntax: 'severity:LEVEL (0-7 or EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG)',
			example: 'severity:CRITICAL',
			note: 'Lower numbers indicate higher severity.',
		},
		log: {
			description: 'Logs this rule match to the error and audit logs.',
			group: 'Non-disruptive',
			syntax: 'log',
			example: 'log',
			note: 'Use this to record rule matches for monitoring and analysis. Combine with pass for non-blocking logging.',
			relatedActions: ['nolog', 'auditlog', 'noauditlog'],
		},
		nolog: {
			description: 'Prevents rule matches from appearing in the error and audit logs.',
			group: 'Non-disruptive',
			syntax: 'nolog',
			example: 'nolog',
			note: 'Use this for rules that perform flow control or set variables without indicating an attack (e.g., whitelisting rules with pass).',
			relatedActions: ['log', 'auditlog', 'noauditlog'],
		},
		deny: {
			description: 'Stops rule processing and intercepts the transaction with the specified status code.',
			group: 'Disruptive',
			syntax: 'deny',
			example: 'SecRule ARGS "@rx attack" "id:1,deny,status:403"',
			note: 'Blocks the request immediately. Default status code is 403 unless specified with status:XXX.',
			relatedActions: ['allow', 'block', 'pass', 'drop', 'redirect'],
		},
		allow: {
			description: 'Stops rule processing and allows the transaction to proceed (whitelist action).',
			group: 'Disruptive',
			syntax: 'allow',
			example: 'allow',
			note: 'Bypasses all remaining rules in the current phase and all subsequent phases. Use for trusted content.',
			relatedActions: ['deny', 'block', 'pass', 'drop', 'redirect'],
		},
		block: {
			description: 'Performs the disruptive action defined by SecDefaultAction.',
			group: 'Disruptive',
			syntax: 'block',
			example: 'block',
			note: 'More flexible than deny - allows you to change the blocking behavior globally via SecDefaultAction instead of editing each rule.',
			relatedActions: ['deny', 'allow', 'pass', 'drop', 'redirect'],
		},
		pass: {
			description: 'Continues processing with the next rule even when this rule matches (non-blocking).',
			group: 'Disruptive',
			syntax: 'pass',
			example: 'pass',
			note: 'Use this when you want to log, set variables, whitelist parameters (ctl:ruleRemoveTargetById), or perform other setup actions without blocking the request.',
			relatedActions: ['deny', 'allow', 'block', 'drop', 'redirect'],
		},
		drop: {
			description: 'In ModSecurity v3, this currently functions the same as deny.',
			group: 'Disruptive',
			syntax: 'drop',
			example: 'drop',
			note: 'Behavior differs from v2 where it would drop the TCP connection.',
			relatedActions: ['deny', 'allow', 'block', 'pass', 'redirect'],
		},
		redirect: {
			description: 'Redirects the transaction to another URL.',
			group: 'Disruptive',
			syntax: 'redirect:URL',
			example: 'redirect:http://www.example.com/error.html',
			note: 'Sends a 302 (Moved Temporarily) response. Stops rule processing.',
			relatedActions: ['deny', 'allow', 'block', 'pass', 'drop'],
		},
		status: {
			description: 'Specifies the response status code to use with deny or redirect actions.',
			group: 'Non-disruptive',
			syntax: 'status:NUMBER',
			example: 'status:403',
			note: 'Common values: 403 (Forbidden), 404 (Not Found), 500 (Internal Server Error)',
		},
		chain: {
			description: 'Chains the current rule with the rule that immediately follows it.',
			group: 'Non-disruptive',
			syntax: 'chain',
			example: 'chain',
			note: 'All rules in a chain must match for the disruptive action to trigger.',
		},
		skip: {
			description: 'Skips one or more rules in the chain on a successful match.',
			group: 'Non-disruptive',
			syntax: 'skip:NUMBER',
			example: 'skip:2',
			note: 'Can only be used in chained rules.',
		},
		skipAfter: {
			description: 'Skips all rules until a rule with the given marker is found.',
			group: 'Non-disruptive',
			syntax: 'skipAfter:MARKER',
			example: 'skipAfter:END_CHECKS',
			note: 'Useful for flow control and conditional rule execution.',
		},
		setvar: {
			description: 'Creates, removes, or updates a variable.',
			group: 'Non-disruptive',
			syntax: 'setvar:NAME=VALUE or setvar:!NAME or setvar:NAME',
			example: 'setvar:tx.score=+5',
			note: 'Can be used for anomaly scoring and session tracking.',
		},
		t: {
			description: 'Applies a transformation function to normalize input data before pattern matching.',
			group: 'Non-disruptive',
			syntax: 't:FUNCTION',
			example: 't:lowercase,t:urlDecode',
			note: 'Chain multiple transformations to apply them in order. Use t:none to clear inherited transformations. Common: lowercase, urlDecode, removeWhitespace, htmlEntityDecode.',
		},
		ctl: {
			description: 'Changes ModSecurity configuration on a transient, per-transaction basis.',
			group: 'Non-disruptive',
			syntax: 'ctl:OPTION=VALUE',
			example: 'ctl:ruleRemoveTargetById=981260;ARGS:user',
			note: 'Any changes made using this action will affect only the current transaction.',
		},
		tag: {
			description: 'Assigns a tag (category) to a rule.',
			group: 'Meta-data',
			syntax: 'tag:TAG_NAME',
			example: 'tag:OWASP_CRS/WEB_ATTACK/XSS',
			note: 'Multiple tags can be specified for a single rule.',
		},
		ver: {
			description: 'Specifies the rule set version.',
			group: 'Meta-data',
			syntax: 'ver:VERSION',
			example: 'ver:1.2.3',
			note: 'Used for tracking rule versions.',
		},
		rev: {
			description: 'Specifies the rule revision.',
			group: 'Meta-data',
			syntax: 'rev:REVISION',
			example: 'rev:2',
			note: 'Used for tracking rule changes.',
		},
		maturity: {
			description: 'Specifies the rule maturity level.',
			group: 'Meta-data',
			syntax: 'maturity:LEVEL (1-9)',
			example: 'maturity:8',
			note: 'Higher numbers indicate more mature/tested rules.',
		},
		accuracy: {
			description: 'Specifies the rule accuracy level.',
			group: 'Meta-data',
			syntax: 'accuracy:LEVEL (1-9)',
			example: 'accuracy:9',
			note: 'Higher numbers indicate lower false positive rates.',
		},
		logdata: {
			description: 'Specifies additional data to be logged with a rule match.',
			group: 'Non-disruptive',
			syntax: 'logdata:"DATA"',
			example: 'logdata:"Matched Data: %{MATCHED_VAR}"',
			note: 'Supports variable expansion.',
		},
		capture: {
			description: 'Copies captured substrings from the regular expression to the transaction collection.',
			group: 'Non-disruptive',
			syntax: 'capture',
			example: 'capture',
			note: 'Captured data is available in TX.0-TX.9 variables.',
		},
		multiMatch: {
			description: 'Forces the rule to match on all occurrences of a variable, not just the first.',
			group: 'Non-disruptive',
			syntax: 'multiMatch',
			example: 'multiMatch',
			note: 'Useful for thorough inspection of multiple values.',
		},
		exec: {
			description: 'Executes an external script supplied as parameter.',
			group: 'Non-disruptive',
			syntax: 'exec:/path/to/script.lua',
			example: 'exec:/usr/local/apache/conf/exec.lua',
			note: 'ModSecurity v3 currently only supports Lua scripts.',
		},
		auditlog: {
			description: 'Marks the transaction to be logged to the audit log.',
			group: 'Non-disruptive',
			syntax: 'auditlog',
			example: 'auditlog',
			note: 'Transaction will be logged regardless of audit engine settings.',
		},
		noauditlog: {
			description: 'Prevents the transaction from being logged to the audit log.',
			group: 'Non-disruptive',
			syntax: 'noauditlog',
			example: 'noauditlog',
			note: 'Useful for reducing audit log noise.',
		},
	},

	operators: {
		rx: {
			description: 'Regular expression match. This is the default operator if none is specified.',
			syntax: '"@rx PATTERN"',
			example: 'SecRule ARGS "@rx <script" "id:1,deny"',
			note: 'Uses PCRE (Perl Compatible Regular Expressions) syntax.',
		},
		pm: {
			description: 'Parallel matching operator that performs case-insensitive matching of multiple patterns at once.',
			syntax: '"@pm PATTERN1 PATTERN2 ..."',
			example: 'SecRule ARGS "@pm attack hack exploit" "id:1,deny"',
			note: 'Much faster than multiple rx operators for simple string matching.',
		},
		eq: {
			description: 'Performs numerical comparison (equal to).',
			syntax: '"@eq NUMBER"',
			example: 'SecRule &ARGS "@eq 0" "id:1,deny"',
			note: 'Used with variable counting (& prefix).',
		},
		ge: {
			description: 'Performs numerical comparison (greater than or equal to).',
			syntax: '"@ge NUMBER"',
			example: 'SecRule REQUEST_BODY_LENGTH "@ge 1000000" "id:1,deny"',
			note: 'Useful for checking sizes and counts.',
		},
		gt: {
			description: 'Performs numerical comparison (greater than).',
			syntax: '"@gt NUMBER"',
			example: 'SecRule TX:anomaly_score "@gt 5" "id:1,deny"',
			note: 'Commonly used for anomaly scoring thresholds.',
		},
		le: {
			description: 'Performs numerical comparison (less than or equal to).',
			syntax: '"@le NUMBER"',
			example: 'SecRule ARGS:age "@le 0" "id:1,deny"',
			note: 'Useful for validation rules.',
		},
		lt: {
			description: 'Performs numerical comparison (less than).',
			syntax: '"@lt NUMBER"',
			example: 'SecRule ARGS:quantity "@lt 1" "id:1,deny"',
			note: 'Useful for validation rules.',
		},
		contains: {
			description: 'String match: checks if the target string contains the parameter string.',
			syntax: '"@contains STRING"',
			example: 'SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:1,deny"',
			note: 'Case-sensitive unless used with t:lowercase.',
		},
		beginsWith: {
			description: 'String match: checks if the target string begins with the parameter string.',
			syntax: '"@beginsWith STRING"',
			example: 'SecRule REQUEST_URI "@beginsWith /admin" "id:1,deny"',
			note: 'Useful for path-based matching.',
		},
		endsWith: {
			description: 'String match: checks if the target string ends with the parameter string.',
			syntax: '"@endsWith STRING"',
			example: 'SecRule REQUEST_FILENAME "@endsWith .php" "id:1,deny"',
			note: 'Useful for file extension checks.',
		},
		streq: {
			description: 'String match: checks if the target string equals the parameter string.',
			syntax: '"@streq STRING"',
			example: 'SecRule REQUEST_METHOD "@streq POST" "id:1,pass"',
			note: 'Case-sensitive exact match.',
		},
		within: {
			description: 'String match: checks if the target string is found within the parameter string.',
			syntax: '"@within STRING"',
			example: 'SecRule REQUEST_METHOD "@within GET POST HEAD" "id:1,pass"',
			note: 'Useful for whitelisting.',
		},
		detectSQLi: {
			description: 'Detects SQL injection attacks using libinjection.',
			syntax: '"@detectSQLi"',
			example: 'SecRule ARGS "@detectSQLi" "id:1,deny,msg:\'SQL Injection\'"',
			note: 'Advanced detection using machine learning techniques.',
		},
		detectXSS: {
			description: 'Detects XSS attacks using libinjection.',
			syntax: '"@detectXSS"',
			example: 'SecRule ARGS "@detectXSS" "id:1,deny,msg:\'XSS Attack\'"',
			note: 'Advanced detection using machine learning techniques.',
		},
		validateByteRange: {
			description: 'Validates that all bytes in the input fall within the specified range.',
			syntax: '"@validateByteRange RANGE1[,RANGE2,...]"',
			example: 'SecRule ARGS "@validateByteRange 32-126" "id:1,deny"',
			note: 'Useful for detecting binary data in text fields.',
		},
		validateUrlEncoding: {
			description: 'Validates the URL encoding in the input.',
			syntax: '"@validateUrlEncoding"',
			example: 'SecRule REQUEST_URI "@validateUrlEncoding" "id:1,deny"',
			note: 'Detects invalid URL encoding that could be used for evasion.',
		},
		validateUtf8Encoding: {
			description: 'Validates the UTF-8 encoding in the input.',
			syntax: '"@validateUtf8Encoding"',
			example: 'SecRule ARGS "@validateUtf8Encoding" "id:1,deny"',
			note: 'Prevents UTF-8 encoding attacks.',
		},
		ipMatch: {
			description: 'Performs a fast IP address match.',
			syntax: '"@ipMatch IP1[,IP2,...]"',
			example: 'SecRule REMOTE_ADDR "@ipMatch 192.168.1.0/24" "id:1,deny"',
			note: 'Supports individual IPs, ranges, and CIDR notation.',
		},
		ipMatchFromFile: {
			description: 'Performs IP address match using IPs from a file.',
			syntax: '"@ipMatchFromFile /path/to/file"',
			example: 'SecRule REMOTE_ADDR "@ipMatchFromFile /etc/modsec/blacklist.txt" "id:1,deny"',
			note: 'File should contain one IP/range per line.',
		},
		geoLookup: {
			description: 'Performs geolocation lookup on the IP address.',
			syntax: '"@geoLookup"',
			example: 'SecRule REMOTE_ADDR "@geoLookup" "chain,id:1"\nSecRule GEO:COUNTRY_CODE "@streq CN" "deny"',
			note: 'Requires GeoIP database configuration.',
		},
		rbl: {
			description: 'Checks the input against a DNS-based blacklist (RBL).',
			syntax: '"@rbl DNSBL_DOMAIN"',
			example: 'SecRule REMOTE_ADDR "@rbl zen.spamhaus.org" "id:1,deny"',
			note: 'Used for checking against spam/malware IP blacklists.',
		},
		verifyCC: {
			description: 'Detects and validates credit card numbers.',
			syntax: '"@verifyCC CARD_TYPES"',
			example: 'SecRule ARGS "@verifyCC VISA MASTERCARD" "id:1,deny,msg:\'Credit Card Found\'"',
			note: 'Uses Luhn algorithm for validation. Helps prevent credit card leakage.',
		},
		verifyCPF: {
			description: 'Validates Brazilian CPF numbers.',
			syntax: '"@verifyCPF"',
			example: 'SecRule ARGS "@verifyCPF" "id:1,deny"',
			note: 'Specific to Brazilian tax IDs.',
		},
		verifySSN: {
			description: 'Validates US Social Security Numbers.',
			syntax: '"@verifySSN"',
			example: 'SecRule ARGS "@verifySSN" "id:1,deny,msg:\'SSN Found\'"',
			note: 'Helps prevent SSN leakage.',
		},
	},

	variables: {
		ARGS: {
			description: 'Contains all request parameters (query string and POST data combined).',
			example: 'SecRule ARGS "@rx attack" "id:1,deny"',
		},
		ARGS_GET: {
			description: 'Contains all query string (GET) parameters.',
			example: 'SecRule ARGS_GET "@rx attack" "id:1,deny"',
		},
		ARGS_POST: {
			description: 'Contains all POST parameters.',
			example: 'SecRule ARGS_POST "@rx attack" "id:1,deny"',
		},
		ARGS_NAMES: {
			description: 'Contains all parameter names (both GET and POST).',
			example: 'SecRule ARGS_NAMES "@rx (cmd|exec)" "id:1,deny"',
		},
		REQUEST_URI: {
			description: 'Contains the full request URI (with query string, but normalized).',
			example: 'SecRule REQUEST_URI "@contains /admin" "id:1,deny"',
		},
		REQUEST_URI_RAW: {
			description: 'Contains the full request URI exactly as it was received (not normalized).',
			example: 'SecRule REQUEST_URI_RAW "@contains %00" "id:1,deny"',
		},
		REQUEST_FILENAME: {
			description: 'Contains the file path portion of the request URI (no query string).',
			example: 'SecRule REQUEST_FILENAME "@endsWith .php" "id:1,pass"',
		},
		REQUEST_METHOD: {
			description: 'Contains the request method (GET, POST, etc.).',
			example: 'SecRule REQUEST_METHOD "!@within GET POST HEAD" "id:1,deny"',
		},
		REQUEST_PROTOCOL: {
			description: 'Contains the request protocol (HTTP/1.0, HTTP/1.1, etc.).',
			example: 'SecRule REQUEST_PROTOCOL "!@streq HTTP/1.1" "id:1,log"',
		},
		REQUEST_HEADERS: {
			description: 'Contains all request headers.',
			example: 'SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:1,deny"',
		},
		REQUEST_HEADERS_NAMES: {
			description: 'Contains all request header names.',
			example: 'SecRule REQUEST_HEADERS_NAMES "@rx ^X-" "id:1,log"',
		},
		REQUEST_COOKIES: {
			description: 'Contains all request cookies.',
			example: 'SecRule REQUEST_COOKIES:sessionid "@rx [^a-zA-Z0-9]" "id:1,deny"',
		},
		REQUEST_COOKIES_NAMES: {
			description: 'Contains all request cookie names.',
			example: 'SecRule REQUEST_COOKIES_NAMES "@rx __" "id:1,log"',
		},
		REQUEST_BODY: {
			description: 'Contains the raw request body (POST data).',
			example: 'SecRule REQUEST_BODY "@contains malware" "id:1,deny"',
		},
		RESPONSE_HEADERS: {
			description: 'Contains all response headers.',
			example: 'SecRule RESPONSE_HEADERS:Content-Type "@contains text/html" "id:1,pass"',
		},
		RESPONSE_BODY: {
			description: 'Contains the response body.',
			example: 'SecRule RESPONSE_BODY "@contains SSN:" "id:1,deny,msg:\'Data Leakage\'"',
		},
		RESPONSE_STATUS: {
			description: 'Contains the response status code.',
			example: 'SecRule RESPONSE_STATUS "@eq 500" "id:1,log,auditlog"',
		},
		REMOTE_ADDR: {
			description: 'Contains the IP address of the remote client.',
			example: 'SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:1,deny"',
		},
		REMOTE_HOST: {
			description: 'Contains the hostname of the remote client (if available).',
			example: 'SecRule REMOTE_HOST "@endsWith .cn" "id:1,log"',
		},
		REMOTE_USER: {
			description: 'Contains the authenticated username (if HTTP authentication is used).',
			example: 'SecRule REMOTE_USER "@streq admin" "id:1,log"',
		},
		TX: {
			description: 'Transaction collection - used for storing temporary data during transaction processing.',
			example: 'SecRule TX:anomaly_score "@gt 5" "id:1,deny"',
		},
		MATCHED_VAR: {
			description: 'Contains the value of the variable that matched in the current rule.',
			example: 'SecRule ARGS "@rx attack" "id:1,deny,msg:\'Attack: %{MATCHED_VAR}\'"',
		},
		MATCHED_VAR_NAME: {
			description: 'Contains the name of the variable that matched in the current rule.',
			example: 'SecRule ARGS "@rx attack" "id:1,deny,msg:\'Attack in %{MATCHED_VAR_NAME}\'"',
		},
		FILES: {
			description: 'Contains uploaded files (multipart/form-data).',
			example: 'SecRule FILES "@rx malware" "id:1,deny"',
		},
		FILES_NAMES: {
			description: 'Contains the names of uploaded files.',
			example: 'SecRule FILES_NAMES "@endsWith .exe" "id:1,deny"',
		},
		XML: {
			description: 'Contains parsed XML data (when requestBodyProcessor=XML is used).',
			example: 'SecRule XML://@username "@contains admin" "id:1,deny"',
		},
		GEO: {
			description: 'Contains geolocation data after @geoLookup operator is used.',
			example: 'SecRule GEO:COUNTRY_CODE "@streq CN" "id:1,deny"',
		},
		DURATION: {
			description: 'Contains the number of milliseconds elapsed since the beginning of the transaction.',
			example: 'SecRule DURATION "@gt 1000" "id:1,log,msg:\'Slow request\'"',
		},
	},
}
