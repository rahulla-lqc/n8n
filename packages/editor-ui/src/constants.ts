import { ILogInStatus, IRole, IUserPermissions } from "./Interface";

export const MAX_DISPLAY_DATA_SIZE = 204800;
export const MAX_DISPLAY_ITEMS_AUTO_ALL = 250;
export const NODE_NAME_PREFIX = 'node-';

export const PLACEHOLDER_FILLED_AT_EXECUTION_TIME = '[filled at execution time]';

// workflows
export const PLACEHOLDER_EMPTY_WORKFLOW_ID = '__EMPTY__';
export const DEFAULT_NODETYPE_VERSION = 1;
export const DEFAULT_NEW_WORKFLOW_NAME = 'My workflow';
export const MIN_WORKFLOW_NAME_LENGTH = 1;
export const MAX_WORKFLOW_NAME_LENGTH = 128;
export const DUPLICATE_POSTFFIX = ' copy';
export const NODE_OUTPUT_DEFAULT_KEY = '_NODE_OUTPUT_DEFAULT_KEY_';

// tags
export const MAX_TAG_NAME_LENGTH = 24;

// modals
export const ABOUT_MODAL_KEY = 'about';
export const CHANGE_PASSWORD_MODAL_KEY = 'changePassword';
export const CREDENTIAL_EDIT_MODAL_KEY = 'editCredential';
export const CREDENTIAL_SELECT_MODAL_KEY = 'selectCredential';
export const DELETE_USER_MODAL_KEY = 'deleteUser';
export const INVITE_USER_MODAL_KEY = 'inviteUser';
export const DUPLICATE_MODAL_KEY = 'duplicate';
export const TAGS_MANAGER_MODAL_KEY = 'tagsManager';
export const WORKFLOW_OPEN_MODAL_KEY = 'workflowOpen';
export const VERSIONS_MODAL_KEY = 'versions';
export const WORKFLOW_SETTINGS_MODAL_KEY = 'settings';
export const CREDENTIAL_LIST_MODAL_KEY = 'credentialsList';
export const PERSONALIZATION_MODAL_KEY = 'personalization';
export const CONTACT_PROMPT_MODAL_KEY = 'contactPrompt';
export const VALUE_SURVEY_MODAL_KEY = 'valueSurvey';

// breakpoints
export const BREAKPOINT_SM = 768;
export const BREAKPOINT_MD = 992;
export const BREAKPOINT_LG = 1200;
export const BREAKPOINT_XL = 1920;


// templates
export const TEMPLATES_BASE_URL = `https://api.n8n.io/`;

// node types
export const CALENDLY_TRIGGER_NODE_TYPE = 'n8n-nodes-base.calendlyTrigger';
export const CRON_NODE_TYPE = 'n8n-nodes-base.cron';
export const CLEARBIT_NODE_TYPE = 'n8n-nodes-base.clearbit';
export const FUNCTION_NODE_TYPE = 'n8n-nodes-base.function';
export const GITHUB_TRIGGER_NODE_TYPE = 'n8n-nodes-base.githubTrigger';
export const ERROR_TRIGGER_NODE_TYPE = 'n8n-nodes-base.errorTrigger';
export const ELASTIC_SECURITY_NODE_TYPE = 'n8n-nodes-base.elasticSecurity';
export const EMAIL_SEND_NODE_TYPE = 'n8n-nodes-base.emailSend';
export const EXECUTE_COMMAND_NODE_TYPE = 'n8n-nodes-base.executeCommand';
export const HTTP_REQUEST_NODE_TYPE = 'n8n-nodes-base.httpRequest';
export const IF_NODE_TYPE = 'n8n-nodes-base.if';
export const ITEM_LISTS_NODE_TYPE = 'n8n-nodes-base.itemLists';
export const JIRA_TRIGGER_NODE_TYPE = 'n8n-nodes-base.jiraTrigger';
export const MICROSOFT_EXCEL_NODE_TYPE = 'n8n-nodes-base.microsoftExcel';
export const MICROSOFT_TEAMS_NODE_TYPE = 'n8n-nodes-base.microsoftTeams';
export const NO_OP_NODE_TYPE = 'n8n-nodes-base.noOp';
export const PAGERDUTY_NODE_TYPE = 'n8n-nodes-base.pagerDuty';
export const SALESFORCE_NODE_TYPE = 'n8n-nodes-base.salesforce';
export const SEGMENT_NODE_TYPE = 'n8n-nodes-base.segment';
export const SET_NODE_TYPE = 'n8n-nodes-base.set';
export const SLACK_NODE_TYPE = 'n8n-nodes-base.slack';
export const SPREADSHEET_FILE_NODE_TYPE = 'n8n-nodes-base.spreadsheetFile';
export const START_NODE_TYPE = 'n8n-nodes-base.start';
export const SWITCH_NODE_TYPE = 'n8n-nodes-base.switch';
export const QUICKBOOKS_NODE_TYPE = 'n8n-nodes-base.quickbooks';
export const WEBHOOK_NODE_TYPE = 'n8n-nodes-base.webhook';
export const XERO_NODE_TYPE = 'n8n-nodes-base.xero';

// Node creator
export const CORE_NODES_CATEGORY = 'Core Nodes';
export const CUSTOM_NODES_CATEGORY = 'Custom Nodes';
export const SUBCATEGORY_DESCRIPTIONS: {
	[category: string]: { [subcategory: string]: string };
} = {
	'Core Nodes': { // this - all subkeys are set from codex
		Flow: 'Branches, core triggers, merge data',
		Files:  'Work with CSV, XML, text, images etc.',
		'Data Transformation': 'Manipulate data fields, run code',
		Helpers: 'HTTP Requests (API calls), date and time, scrape HTML',
	},
};
export const REGULAR_NODE_FILTER = 'Regular';
export const TRIGGER_NODE_FILTER = 'Trigger';
export const ALL_NODE_FILTER = 'All';
export const UNCATEGORIZED_CATEGORY = 'Miscellaneous';
export const UNCATEGORIZED_SUBCATEGORY = 'Helpers';
export const PERSONALIZED_CATEGORY = 'Suggested Nodes ✨';
export const HIDDEN_NODES = [START_NODE_TYPE];

export const REQUEST_NODE_FORM_URL = 'https://n8n-community.typeform.com/to/K1fBVTZ3';

// General
export const INSTANCE_ID_HEADER = 'n8n-instance-id';
export const WAIT_TIME_UNLIMITED = '3000-01-01T00:00:00.000Z';

export const WORK_AREA_KEY = 'workArea';
export const FINANCE_WORK_AREA = 'finance';
export const HR_WORK_AREA = 'HR';
export const IT_ENGINEERING_WORK_AREA = 'IT-Engineering';
export const LEGAL_WORK_AREA = 'legal';
export const MARKETING_WORK_AREA = 'marketing-growth';
export const PRODUCT_WORK_AREA = 'product';
export const SALES_BUSINESSDEV_WORK_AREA = 'sales-businessDevelopment';
export const SECURITY_WORK_AREA = 'security';
export const SUPPORT_WORK_AREA = 'support';
export const OPS_WORK_AREA = 'ops';
export const EXECUTIVE_WORK_AREA = 'executive';
export const OTHER_WORK_AREA_OPTION = 'other';
export const NOT_APPLICABLE_WORK_AREA = 'n/a';

export const COMPANY_INDUSTRY_KEY = 'companyIndustry';
export const E_COMMERCE_INDUSTRY = 'e-commerce';
export const AUTOMATION_CONSULTING_INDUSTRY = 'automation-consulting';
export const SYSTEM_INTEGRATION_INDUSTRY = 'systems-integration';
export const GOVERNMENT_INDUSTRY = 'government';
export const LEGAL_INDUSTRY = 'legal-industry';
export const HEALTHCARE_INDUSTRY= 'healthcare';
export const FINANCE_INDUSTRY = 'finance-industry';
export const SECURITY_INDUSTRY = 'security-industry';
export const SAAS_INDUSTRY = 'saas';
export const OTHER_INDUSTRY_OPTION= 'other';

export const COMPANY_SIZE_KEY = 'companySize';
export const COMPANY_SIZE_20_OR_LESS = '<20';
export const COMPANY_SIZE_20_99 = '20-99';
export const COMPANY_SIZE_100_499 = '100-499';
export const COMPANY_SIZE_500_999 = '500-999';
export const COMPANY_SIZE_1000_OR_MORE = '1000+';
export const COMPANY_SIZE_PERSONAL_USE = 'personalUser';

export const CODING_SKILL_KEY = 'codingSkill';
export const OTHER_WORK_AREA_KEY = 'otherWorkArea';
export const OTHER_COMPANY_INDUSTRY_KEY = 'otherCompanyIndustry';

export const ROLE: {Owner: IRole, Member: IRole, Default: IRole} = {
	Owner: 'owner',
	Member: 'member',
	Default: 'default', // default user with no email when setting up instance
};

export const LOGIN_STATUS: {LoggedIn: ILogInStatus, LoggedOut: ILogInStatus} = {
	LoggedIn: 'LoggedIn', // Can be owner or member or default user
	LoggedOut: 'LoggedOut', // Can only be logged out if UM has been setup
};

export const PERMISSIONS: IUserPermissions = {
	ROUTES: {
		ExecutionById: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedIn],
			},
		},
		NodeViewNew: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedIn],
			},
		},
		NodeViewExisting: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedIn],
			},
		},
		WorkflowTemplate: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedIn],
			},
		},
		SigninView: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedOut],
			},
		},
		SignupView: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedOut],
			},
		},
		SetupView: {
			allow: {
				role: [ROLE.Default],
			},
			deny: {
				um: false,
			},
		},
		ForgotMyPasswordView: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedOut],
			},
		},
		ChangePasswordView: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedOut],
			},
		},
		SettingsRedirect: {
			allow: {
				role: [ROLE.Default, ROLE.Owner],
			},
		},
		UsersSettings: {
			allow: {
				role: [ROLE.Default, ROLE.Owner],
			},
			deny: {
				um: false,
			},
		},
		PersonalSettings: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedIn],
			},
			deny: {
				role: [ROLE.Default],
			},
		},
		NotFoundView: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedIn, LOGIN_STATUS.LoggedOut],
			},
		},
	},
	TAGS: {
		CAN_DELETE_TAGS: {
			allow: {
				role: [ROLE.Owner, ROLE.Default],
			},
		},
	},
	PRIMARY_MENU: {
		CAN_ACCESS_USER_INFO: {
			allow: {
				loginStatus: [LOGIN_STATUS.LoggedIn],
			},
			deny: {
				role: [ROLE.Default],
			},
		},
	},
};
export const VALID_EMAIL_REGEX = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

