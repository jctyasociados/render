"""empty message

Revision ID: 4a431b455556
Revises: 
Create Date: 2025-03-11 18:58:40.173586

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4a431b455556'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('imagedata',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=255), nullable=True),
    sa.Column('image_name', sa.String(length=255), nullable=True),
    sa.Column('image_url', sa.String(length=1000), nullable=True),
    sa.Column('width', sa.String(length=10), nullable=True),
    sa.Column('height', sa.String(length=10), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_imagedata_user_id'), 'imagedata', ['user_id'], unique=False)
    op.create_table('invoice-items',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=255), nullable=True),
    sa.Column('invoice_number', sa.Integer(), nullable=True),
    sa.Column('item_desc', sa.String(length=100), nullable=True),
    sa.Column('item_price', sa.Float(), nullable=True),
    sa.Column('item_quant', sa.Float(), nullable=True),
    sa.Column('amount', sa.Float(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_invoice-items_user_id'), 'invoice-items', ['user_id'], unique=False)
    op.create_table('invoicedata',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=255), nullable=True),
    sa.Column('invoice_number', sa.String(length=100), nullable=True),
    sa.Column('businessname', sa.String(length=100), nullable=True),
    sa.Column('email', sa.String(length=150), nullable=True),
    sa.Column('ein', sa.String(length=100), nullable=True),
    sa.Column('address', sa.String(length=255), nullable=True),
    sa.Column('address2', sa.String(length=255), nullable=True),
    sa.Column('city', sa.String(length=30), nullable=True),
    sa.Column('state', sa.String(length=30), nullable=True),
    sa.Column('zip', sa.String(length=30), nullable=True),
    sa.Column('checkbox', sa.String(length=5), nullable=True),
    sa.Column('businessname_shipping', sa.String(length=100), nullable=True),
    sa.Column('email_shipping', sa.String(length=150), nullable=True),
    sa.Column('ein_shipping', sa.String(length=100), nullable=True),
    sa.Column('address_shipping', sa.String(length=255), nullable=True),
    sa.Column('address2_shipping', sa.String(length=255), nullable=True),
    sa.Column('city_shipping', sa.String(length=30), nullable=True),
    sa.Column('state_shipping', sa.String(length=30), nullable=True),
    sa.Column('zip_shipping', sa.String(length=30), nullable=True),
    sa.Column('invoice_date', sa.Date(), nullable=True),
    sa.Column('taxes', sa.String(length=10), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_invoicedata_user_id'), 'invoicedata', ['user_id'], unique=False)
    op.create_table('invoicevalues',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=255), nullable=True),
    sa.Column('invoice_number', sa.Integer(), nullable=True),
    sa.Column('subtotal', sa.Float(), nullable=True),
    sa.Column('taxes', sa.Float(), nullable=True),
    sa.Column('total', sa.Float(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_invoicevalues_user_id'), 'invoicevalues', ['user_id'], unique=False)
    op.create_table('profiledata',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=255), nullable=True),
    sa.Column('businessname', sa.String(length=255), nullable=True),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('ein', sa.String(length=255), nullable=True),
    sa.Column('address1', sa.String(length=255), nullable=True),
    sa.Column('address2', sa.String(length=255), nullable=True),
    sa.Column('city', sa.String(length=255), nullable=True),
    sa.Column('state', sa.String(length=255), nullable=True),
    sa.Column('zip', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_profiledata_user_id'), 'profiledata', ['user_id'], unique=False)
    op.create_table('qrcodedata',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=255), nullable=True),
    sa.Column('image_name', sa.String(length=255), nullable=True),
    sa.Column('image_url', sa.String(length=1000), nullable=True),
    sa.Column('width', sa.String(length=10), nullable=True),
    sa.Column('height', sa.String(length=10), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_qrcodedata_user_id'), 'qrcodedata', ['user_id'], unique=False)
    op.create_table('templatedata',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('client_email', sa.String(length=255), nullable=True),
    sa.Column('user_id', sa.String(length=255), nullable=True),
    sa.Column('template_url', sa.String(length=2000), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_templatedata_user_id'), 'templatedata', ['user_id'], unique=False)
    op.create_table('templatehtmldata',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('client_email', sa.String(length=255), nullable=True),
    sa.Column('user_id', sa.String(length=255), nullable=True),
    sa.Column('template_url', sa.String(length=2000), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_templatehtmldata_user_id'), 'templatehtmldata', ['user_id'], unique=False)
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=20), nullable=True),
    sa.Column('user_id_hash', sa.String(length=255), nullable=True),
    sa.Column('password', sa.String(length=255), nullable=True),
    sa.Column('email', sa.String(length=60), nullable=True),
    sa.Column('confirmed', sa.Boolean(), nullable=False),
    sa.Column('confirmed_on', sa.DateTime(), nullable=True),
    sa.Column('registered_on', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_user_id_hash'), 'users', ['user_id_hash'], unique=False)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_user_id_hash'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_templatehtmldata_user_id'), table_name='templatehtmldata')
    op.drop_table('templatehtmldata')
    op.drop_index(op.f('ix_templatedata_user_id'), table_name='templatedata')
    op.drop_table('templatedata')
    op.drop_index(op.f('ix_qrcodedata_user_id'), table_name='qrcodedata')
    op.drop_table('qrcodedata')
    op.drop_index(op.f('ix_profiledata_user_id'), table_name='profiledata')
    op.drop_table('profiledata')
    op.drop_index(op.f('ix_invoicevalues_user_id'), table_name='invoicevalues')
    op.drop_table('invoicevalues')
    op.drop_index(op.f('ix_invoicedata_user_id'), table_name='invoicedata')
    op.drop_table('invoicedata')
    op.drop_index(op.f('ix_invoice-items_user_id'), table_name='invoice-items')
    op.drop_table('invoice-items')
    op.drop_index(op.f('ix_imagedata_user_id'), table_name='imagedata')
    op.drop_table('imagedata')
    # ### end Alembic commands ###
