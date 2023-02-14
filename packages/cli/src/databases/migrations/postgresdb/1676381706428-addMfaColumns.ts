import { MigrationInterface, QueryRunner } from 'typeorm';
import { getTablePrefix, logMigrationEnd, logMigrationStart } from '@db/utils/migrationHelpers';

export class AddMfaColumns1676381706428 implements MigrationInterface {
	name = 'AddMfaColumns1676381706428';

	async up(queryRunner: QueryRunner) {
		logMigrationStart(this.name);

		const tablePrefix = getTablePrefix();

		await queryRunner.query(
			`ALTER TABLE "${tablePrefix}user" ADD COLUMN "mfaEnabled" boolean DEFAULT false`,
		);
		await queryRunner.query(
			`ALTER TABLE "${tablePrefix}user" ADD COLUMN "mfaSecret" varchar DEFAULT NULL`,
		);
		await queryRunner.query(
			`ALTER TABLE "${tablePrefix}user" ADD COLUMN "mfaRecoveryCodes" varchar DEFAULT NULL`,
		);

		logMigrationEnd(this.name);
	}

	async down(queryRunner: QueryRunner) {
		const tablePrefix = getTablePrefix();
		await queryRunner.query(`ALTER TABLE "${tablePrefix}user" DROP COLUMN "mfaEnabled"`);
		await queryRunner.query(`ALTER TABLE "${tablePrefix}user" DROP COLUMN "mfaSecret"`);
		await queryRunner.query(`ALTER TABLE "${tablePrefix}user" DROP COLUMN "mfaRecoveryCodes"`);
	}
}