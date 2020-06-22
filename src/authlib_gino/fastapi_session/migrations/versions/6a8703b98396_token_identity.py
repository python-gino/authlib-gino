"""token identity

Revision ID: 6a8703b98396
Revises: a36c9db3f264
Create Date: 2020-06-21 23:47:11.981713

"""
import sqlalchemy as sa
from alembic import op
from authlib.common.security import generate_token

# revision identifiers, used by Alembic.
revision = "6a8703b98396"
down_revision = "a36c9db3f264"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("identities", "id", type_=sa.Text(), server_default=None)
    conn = op.get_bind()
    for (idid,) in conn.execute("SELECT id FROM identities").fetchall():
        op.execute(
            f"UPDATE identities SET id = 'idt:{generate_token(42)}' WHERE id = '{idid}'"
        )
    op.add_column(
        "authorization_codes", sa.Column("identity_id", sa.Text(), nullable=False)
    )
    op.create_foreign_key(
        None, "authorization_codes", "identities", ["identity_id"], ["id"]
    )
    op.add_column("bearer_tokens", sa.Column("identity_id", sa.Text(), nullable=False))
    op.create_foreign_key(None, "bearer_tokens", "identities", ["identity_id"], ["id"])
    op.add_column(
        "sessions", sa.Column("current_identity_id", sa.Text(), nullable=False)
    )
    op.create_foreign_key(
        None, "sessions", "identities", ["current_identity_id"], ["id"]
    )


def downgrade():
    op.drop_column("sessions", "current_identity_id")
    op.drop_column("bearer_tokens", "identity_id")
    op.drop_column("authorization_codes", "identity_id")
    op.alter_column(
        "identities",
        "id",
        type_=sa.BigInteger(),
        postgresql_using="nextval('identities_id_seq')",
        server_default=sa.text("nextval('identities_id_seq')"),
    )
