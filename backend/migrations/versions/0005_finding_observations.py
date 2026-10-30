"""Persist normalized finding observations for graph reconstruction."""
from alembic import op
import sqlalchemy as sa

revision = "0005_finding_observations"
down_revision = "0004_tool_execution_request_count"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("findings")}
    if "observations" not in columns:
        op.add_column("findings", sa.Column("observations", sa.JSON(), nullable=True))


def downgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("findings")}
    if "observations" in columns:
        op.drop_column("findings", "observations")