import { INodeProperties } from 'n8n-workflow';
import * as del from './delete.operation';
import * as get from './get.operation';
import * as getAll from './getAll.operation';
import * as reply from './reply.operation';
import * as send from './send.operation';
import * as update from './update.operation';

export { del as delete, get, getAll, reply, send, update };

export const description: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: {
			show: {
				resource: ['message'],
			},
		},
		options: [
			{
				name: 'Delete',
				value: 'delete',
				description: 'Delete a message',
				action: 'Delete a message',
			},
			{
				name: 'Get',
				value: 'get',
				description: 'Get a single message',
				action: 'Get a message',
			},
			{
				name: 'Get Many',
				value: 'getAll',
				description: "Get many messages in the signed-in user's mailbox",
				action: 'Get many messages',
			},
			{
				name: 'Reply',
				value: 'reply',
				description: 'Create reply to a message',
				action: 'Reply to a message',
			},
			{
				name: 'Send',
				value: 'send',
				description: 'Send a message',
				action: 'Send a message',
			},
			{
				name: 'Update',
				value: 'update',
				description: 'Update a message',
				action: 'Update a message',
			},
		],
		default: 'send',
	},
	{
		displayName: 'Message ID',
		name: 'messageId',
		type: 'string',
		required: true,
		default: '',
		displayOptions: {
			show: {
				resource: ['message'],
				operation: ['delete', 'get', 'getMime', 'move', 'update', 'reply'],
			},
		},
	},

	...del.description,
	...get.description,
	...getAll.description,
	...reply.description,
	...send.description,
	...update.description,
];
