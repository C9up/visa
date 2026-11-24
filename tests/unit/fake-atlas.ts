/**
 * A table engine with the semantics the atlas store relies on, and no others:
 * WHERE narrows, `whereNull` means IS NULL, and an UPDATE answers how many
 * rows it touched. Shared scaffolding, not a `.test.ts`.
 */

import type { AtlasDb, AtlasQuery } from "../../src/stores/atlas.js";

type Row = Record<string, unknown>;

/** A tiny engine with the semantics the store relies on, and no others. */
export class FakeDb implements AtlasDb {
	readonly tables = new Map<string, Row[]>();
	/** Every statement, so a test can assert one UPDATE rather than read-then-write. */
	readonly statements: string[] = [];

	rows(table: string): Row[] {
		let rows = this.tables.get(table);
		if (rows === undefined) {
			rows = [];
			this.tables.set(table, rows);
		}
		return rows;
	}

	from(table: string): AtlasQuery {
		return new FakeQuery(this, table);
	}

	table(table: string): AtlasQuery {
		return new FakeQuery(this, table);
	}
}

type Condition = (row: Row) => boolean;

class FakeQuery implements AtlasQuery {
	readonly #db: FakeDb;
	readonly #table: string;
	readonly #conditions: Condition[] = [];

	constructor(db: FakeDb, table: string) {
		this.#db = db;
		this.#table = table;
	}

	where(conditions: Row): AtlasQuery;
	where(column: string, operator: string, value: unknown): AtlasQuery;
	where(
		conditionsOrColumn: Row | string,
		operator?: string,
		value?: unknown,
	): AtlasQuery {
		if (typeof conditionsOrColumn === "string") {
			const column = conditionsOrColumn;
			this.#conditions.push((row) => compare(row[column], operator, value));
			return this;
		}
		for (const [column, expected] of Object.entries(conditionsOrColumn)) {
			this.#conditions.push((row) => row[column] === expected);
		}
		return this;
	}

	whereNull(column: string): AtlasQuery {
		this.#conditions.push(
			(row) => row[column] === null || row[column] === undefined,
		);
		return this;
	}

	orderBy(column: string, direction: "asc" | "desc" = "asc"): AtlasQuery {
		const rows = this.#matching();
		rows.sort((a, b) => {
			const left = String(a[column] ?? "");
			const right = String(b[column] ?? "");
			return direction === "asc"
				? left.localeCompare(right)
				: right.localeCompare(left);
		});
		return this;
	}

	#matching(): Row[] {
		return this.#db
			.rows(this.#table)
			.filter((row) => this.#conditions.every((condition) => condition(row)));
	}

	async first(): Promise<Row | null> {
		this.#db.statements.push(`select ${this.#table}`);
		return this.#matching()[0] ?? null;
	}

	async exec(): Promise<Row[]> {
		this.#db.statements.push(`select ${this.#table}`);
		return this.#matching();
	}

	async insert(data: Row): Promise<void> {
		this.#db.statements.push(`insert ${this.#table}`);
		this.#db.rows(this.#table).push({ ...data });
	}

	async update(data: Row): Promise<number> {
		this.#db.statements.push(`update ${this.#table}`);
		const rows = this.#matching();
		for (const row of rows) Object.assign(row, data);
		return rows.length;
	}

	async delete(): Promise<number> {
		this.#db.statements.push(`delete ${this.#table}`);
		const matching = new Set(this.#matching());
		const kept = this.#db.rows(this.#table).filter((row) => !matching.has(row));
		this.#db.tables.set(this.#table, kept);
		return matching.size;
	}
}

function compare(left: unknown, operator: string | undefined, right: unknown) {
	const a = left instanceof Date ? left.getTime() : Number(left);
	const b = right instanceof Date ? right.getTime() : Number(right);
	if (operator === "<") return a < b;
	if (operator === ">") return a > b;
	return left === right;
}
