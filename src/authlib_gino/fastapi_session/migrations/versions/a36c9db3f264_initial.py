"""initial

Revision ID: a36c9db3f264
Revises:
Create Date: 2020-06-06 01:07:56.222696

"""
import time

import sqlalchemy as sa
from alembic import op
from authlib.common.security import generate_token
from sqlalchemy.dialects import postgresql

revision = "a36c9db3f264"
down_revision = None
branch_labels = ("session",)
depends_on = None


def upgrade():
    users = op.create_table(
        "users",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("profile", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    root_id = f"usr:{generate_token(42)}"
    op.execute(
        users.insert()
        .values(id=root_id, created_at=int(time.time()), profile=dict(name="root"))
        .returning(users.c.id)
    )
    clients = op.create_table(
        "clients",
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("client_secret", sa.Text(), nullable=True),
        sa.Column(
            "_client_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("client_id_issued_at", sa.Integer(), nullable=False),
        sa.Column("client_secret_expires_at", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],),
        sa.PrimaryKeyConstraint("client_id"),
    )
    op.execute(
        clients.insert().values(
            user_id=root_id,
            client_id=f"cli:swagger-ui",
            _client_metadata=dict(
                redirect_uris=["http://localhost:8000/docs/oauth2-redirect"],
                token_endpoint_auth_method="none",
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                client_name="Swagger UI",
                scope="openid admin",
            ),
            is_active=True,
            client_id_issued_at=int(time.time()),
            client_secret_expires_at=0,
        )
    )
    op.create_table(
        "identities",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("sub", sa.String(), nullable=False),
        sa.Column("idp", sa.String(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("profile", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("identities_idp_sub_idx", "identities", ["sub", "idp"], unique=True)
    op.create_table(
        "authorization_codes",
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("code", sa.Text(), nullable=False),
        sa.Column("code_challenge_method", sa.Text(), nullable=True),
        sa.Column("used", sa.Boolean(), nullable=True),
        sa.Column("redirect_uri", sa.Text(), nullable=True),
        sa.Column("response_type", sa.Text(), nullable=True),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("nonce", sa.Text(), nullable=True),
        sa.Column("auth_time", sa.Integer(), nullable=False),
        sa.Column("code_challenge", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"],),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],),
        sa.PrimaryKeyConstraint("code"),
    )
    op.create_index(
        "auth_code_nonce_index",
        "authorization_codes",
        ["nonce", "auth_time"],
        unique=False,
        postgresql_where=sa.text("not used"),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("terminated_at", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"],),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "bearer_tokens",
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("refresh_token", sa.Text(), nullable=False),
        sa.Column("access_token", sa.Text(), nullable=False),
        sa.Column("token_type", sa.Text(), nullable=True),
        sa.Column("revoked_at", sa.Integer(), nullable=True),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("issued_at", sa.Integer(), nullable=False),
        sa.Column("expires_in", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"],),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"],),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],),
        sa.PrimaryKeyConstraint("refresh_token"),
    )


def downgrade():
    op.drop_table("bearer_tokens")
    op.drop_table("sessions")
    op.drop_index("auth_code_nonce_index", table_name="authorization_codes")
    op.drop_table("authorization_codes")
    op.drop_index("identities_idp_sub_idx", table_name="identities")
    op.drop_table("identities")
    op.drop_table("clients")
    op.drop_table("users")
