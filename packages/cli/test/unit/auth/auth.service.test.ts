import jwt from 'jsonwebtoken';
import { mock } from 'jest-mock-extended';

import { AuthService } from '@/auth/auth.service';
import config from '@/config';
import { Time } from '@/constants';
import type { User } from '@db/entities/User';
import type { UserRepository } from '@db/repositories/user.repository';
import { JwtService } from '@/services/jwt.service';

describe('AuthService', () => {
	config.set('userManagement.jwtSecret', 'random-secret');

	const user = mock<User>({ id: '123', password: 'passwordHash' });
	const jwtService = new JwtService(mock());
	const userRepository = mock<UserRepository>();
	const authService = new AuthService(mock(), mock(), jwtService, mock(), userRepository);

	describe('issueJWT', () => {
		describe('when not setting userManagement.jwtSessionDuration', () => {
			it('should default to expire in 7 days', () => {
				const defaultInSeconds = 7 * Time.days.toSeconds;
				const mockUser = mock<User>({ password: 'passwordHash' });
				const token = authService.issueJWT(mockUser);

				expect(authService.jwtExpiration).toBe(defaultInSeconds);
				const decodedToken = jwtService.verify(token);
				if (decodedToken.exp === undefined || decodedToken.iat === undefined) {
					fail('Expected exp and iat to be defined');
				}

				expect(decodedToken.exp - decodedToken.iat).toBe(defaultInSeconds);
			});
		});

		describe('when setting userManagement.jwtSessionDuration', () => {
			const testDurationHours = 1;
			const testDurationSeconds = testDurationHours * Time.hours.toSeconds;
			config.set('userManagement.jwtSessionDurationHours', testDurationHours);
			const authService = new AuthService(mock(), mock(), jwtService, mock(), userRepository);

			it('should apply it to tokens', () => {
				const mockUser = mock<User>({ password: 'passwordHash' });
				const token = authService.issueJWT(mockUser);

				// expect(expiresIn).toBe(testDurationSeconds);
				const decodedToken = jwtService.verify(token);
				if (decodedToken.exp === undefined || decodedToken.iat === undefined) {
					fail('Expected exp and iat to be defined on decodedToken');
				}
				expect(decodedToken.exp - decodedToken.iat).toBe(testDurationSeconds);
			});
		});
	});

	describe('generatePasswordResetToken', () => {
		it('should generate valid password-reset tokens', () => {
			const token = authService.generatePasswordResetToken(user);

			const decoded = jwt.decode(token) as jwt.JwtPayload;

			if (!decoded.exp) fail('Token does not contain expiry');
			if (!decoded.iat) fail('Token does not contain issued-at');

			expect(decoded.sub).toEqual(user.id);
			expect(decoded.exp - decoded.iat).toEqual(1200); // Expires in 20 minutes
			expect(decoded.passwordSha).toEqual(
				'31513c5a9e3c5afe5c06d5675ace74e8bc3fadd9744ab5d89c311f2a62ccbd39',
			);
		});
	});

	describe('resolvePasswordResetToken', () => {
		it('should not return a user if the token in invalid', async () => {
			const resolvedUser = await authService.resolvePasswordResetToken('invalid-token');
			expect(resolvedUser).toBeUndefined();
		});

		it('should not return a user if the token in expired', async () => {
			const token = authService.generatePasswordResetToken(user, '-1h');

			const resolvedUser = await authService.resolvePasswordResetToken(token);
			expect(resolvedUser).toBeUndefined();
		});

		it('should not return a user if the user does not exist in the DB', async () => {
			userRepository.findOne.mockResolvedValueOnce(null);
			const token = authService.generatePasswordResetToken(user);

			const resolvedUser = await authService.resolvePasswordResetToken(token);
			expect(resolvedUser).toBeUndefined();
		});

		it('should not return a user if the password sha does not match', async () => {
			const token = authService.generatePasswordResetToken(user);
			const updatedUser = Object.create(user);
			updatedUser.password = 'something-else';
			userRepository.findOne.mockResolvedValueOnce(updatedUser);

			const resolvedUser = await authService.resolvePasswordResetToken(token);
			expect(resolvedUser).toBeUndefined();
		});

		it('should not return the user if all checks pass', async () => {
			const token = authService.generatePasswordResetToken(user);
			userRepository.findOne.mockResolvedValueOnce(user);

			const resolvedUser = await authService.resolvePasswordResetToken(token);
			expect(resolvedUser).toEqual(user);
		});
	});
});
