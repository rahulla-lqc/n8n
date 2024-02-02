import { Service } from 'typedi';
import type { RequestHandler, Response } from 'express';
import { createHash } from 'crypto';
import { JsonWebTokenError, type JwtPayload } from 'jsonwebtoken';
import { ApplicationError } from 'n8n-workflow';

import config from '@/config';
import { AUTH_COOKIE_NAME, RESPONSE_ERROR_MESSAGES, Time } from '@/constants';
import type { User } from '@db/entities/User';
import { UserRepository } from '@db/repositories/user.repository';
import type { AuthRole } from '@/decorators/types';
import { AuthError } from '@/errors/response-errors/auth.error';
import { UnauthorizedError } from '@/errors/response-errors/unauthorized.error';
import { License } from '@/License';
import { Logger } from '@/Logger';
import type { AuthenticatedRequest } from '@/requests';
import { JwtService } from '@/services/jwt.service';
import { UrlService } from '@/services/url.service';

interface AuthJwtPayload {
	id: string;
	email: string | null;
	password: string | null;
}

@Service()
export class AuthService {
	private middlewareCache = new Map<string, RequestHandler>();

	/** How many **milliseconds** before a JWT expires should it be renewed */
	private jwtRefreshTimeout: number;

	/** How many **seconds** is an issues JWT valid for */
	readonly jwtExpiration: number;

	constructor(
		private readonly logger: Logger,
		private readonly license: License,
		private readonly jwtService: JwtService,
		private readonly urlService: UrlService,
		private readonly userRepository: UserRepository,
	) {
		const { jwtRefreshTimeoutHours, jwtSessionDurationHours } = config.get('userManagement');
		if (jwtRefreshTimeoutHours === 0) {
			this.jwtRefreshTimeout = Math.floor(
				jwtSessionDurationHours * 0.25 * Time.hours.toMilliseconds,
			);
		} else {
			this.jwtRefreshTimeout = Math.floor(jwtRefreshTimeoutHours * Time.hours.toMilliseconds);
		}

		this.jwtExpiration = jwtSessionDurationHours * Time.hours.toSeconds;
	}

	createAuthMiddleware(authRole: AuthRole): RequestHandler {
		const { middlewareCache: cache } = this;
		let authMiddleware = cache.get(authRole);
		if (authMiddleware) return authMiddleware;

		authMiddleware = async (req: AuthenticatedRequest, res, next) => {
			if (authRole === 'none') return next();

			const token = req.cookies[AUTH_COOKIE_NAME];
			if (token) {
				try {
					const resolved = await this.resolveJwt(token);
					if (resolved.expiresAt * 1000 - Date.now() < this.jwtRefreshTimeout) {
						this.logger.debug('JWT about to expire. Will be refreshed');
						this.issueCookie(res, resolved.user);
					}
					req.user = resolved.user;
				} catch (error) {
					if (error instanceof JsonWebTokenError || error instanceof AuthError) {
						this.clearCookie(res);
					} else {
						throw error;
					}
				}
			}

			if (!req.user) return res.status(401).json({ status: 'error', message: 'Unauthorized' });

			if (authRole === 'any' || authRole === req.user.role) return next();

			res.status(403).json({ status: 'error', message: 'Unauthorized' });
		};

		cache.set(authRole, authMiddleware);
		return authMiddleware;
	}

	clearCookie(res: Response) {
		res.clearCookie(AUTH_COOKIE_NAME);
	}

	issueCookie(res: Response, user: User) {
		// If the instance has exceeded its user quota, prevent non-owners from logging in
		const isWithinUsersLimit = this.license.isWithinUsersLimit();
		if (
			config.getEnv('userManagement.isInstanceOwnerSetUp') &&
			!user.isOwner &&
			!isWithinUsersLimit
		) {
			throw new UnauthorizedError(RESPONSE_ERROR_MESSAGES.USERS_QUOTA_REACHED);
		}

		const token = this.issueJWT(user);
		res.cookie(AUTH_COOKIE_NAME, token, {
			maxAge: this.jwtExpiration * Time.seconds.toMilliseconds,
			httpOnly: true,
			sameSite: 'lax',
		});
	}

	issueJWT(user: User) {
		const { id, email, password } = user;
		const payload: AuthJwtPayload = {
			id,
			email,
			password: password ?? null,
		};
		if (password) {
			payload.password = createHash('sha256')
				.update(password.slice(password.length / 2))
				.digest('hex');
		}

		return this.jwtService.sign(payload, {
			expiresIn: this.jwtExpiration,
		});
	}

	async resolveJwt(token: string) {
		const jwtPayload: AuthJwtPayload & { exp: number } = this.jwtService.verify(token, {
			algorithms: ['HS256'],
		});

		// TODO: Use an in-memory ttl-cache to cache the User object for upto a minute
		const user = await this.userRepository.findOne({
			where: { id: jwtPayload.id },
		});

		let passwordHash = null;
		if (user?.password) {
			passwordHash = this.createPasswordSha(user);
		}

		// currently only LDAP users during synchronization
		// can be set to disabled
		if (user?.disabled) {
			throw new AuthError('Unauthorized');
		}

		if (!user || jwtPayload.password !== passwordHash || user.email !== jwtPayload.email) {
			// When owner hasn't been set up, the default user
			// won't have email nor password (both equals null)
			throw new ApplicationError('Invalid token content');
		}

		return {
			user,
			/** Duration in seconds when this JWT expires */
			expiresAt: jwtPayload.exp,
		};
	}

	generatePasswordResetToken(user: User, expiresIn = '20m') {
		return this.jwtService.sign(
			{ sub: user.id, passwordSha: this.createPasswordSha(user) },
			{ expiresIn },
		);
	}

	generatePasswordResetUrl(user: User) {
		const instanceBaseUrl = this.urlService.getInstanceBaseUrl();
		const url = new URL(`${instanceBaseUrl}/change-password`);

		url.searchParams.append('token', this.generatePasswordResetToken(user));
		url.searchParams.append('mfaEnabled', user.mfaEnabled.toString());

		return url.toString();
	}

	async resolvePasswordResetToken(token: string): Promise<User | undefined> {
		let decodedToken: JwtPayload & { passwordSha: string };
		try {
			decodedToken = this.jwtService.verify(token);
		} catch (e) {
			if (e instanceof TokenExpiredError) {
				this.logger.debug('Reset password token expired', { token });
			} else {
				this.logger.debug('Error verifying token', { token });
			}
			return;
		}

		const user = await this.userRepository.findOne({
			where: { id: decodedToken.sub },
			relations: ['authIdentities'],
		});

		if (!user) {
			this.logger.debug(
				'Request to resolve password token failed because no user was found for the provided user ID',
				{ userId: decodedToken.sub, token },
			);
			return;
		}

		if (this.createPasswordSha(user) !== decodedToken.passwordSha) {
			this.logger.debug('Password updated since this token was generated');
			return;
		}

		return user;
	}

	private createPasswordSha({ password }: User) {
		return createHash('sha256')
			.update(password.slice(password.length / 2))
			.digest('hex');
	}
}
