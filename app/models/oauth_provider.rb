# frozen_string_literal: true

# Redmine plugin OAuth
#
# Karel Pičman <karel.picman@kontron.com>
#
# This file is part of Redmine OAuth plugin.
#
# Redmine OAuth plugin is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# Redmine OAuth plugin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with Redmine OAuth plugin. If not, see
# <https://www.gnu.org/licenses/>.

# OauthProvider model class
class OauthProvider < ApplicationRecord
  validates :oauth_name, presence: true
  validates :site, format: { without: /\.ru\b/ }, length: { maximum: 256 }
  validates :client_id, presence: true, length: { maximum: 256 }
  validates :client_secret, presence: true, length: { maximum: 128 } # Must be longer due to an optional cyphering
  validates :tenant_id, length: { maximum: 40 }
  validates :custom_name, presence: true, uniqueness: true, length: { maximum: 30 }
  validates :custom_auth_endpoint, length: { maximum: 256 }
  validates :custom_auth_endpoint, presence: true, if: proc { |p| p.custom_name == 'Custom' }
  validates :custom_token_endpoint, length: { maximum: 256 }
  validates :custom_token_endpoint, presence: true, if: proc { |p| p.custom_name == 'Custom' }
  validates :custom_profile_endpoint, length: { maximum: 256 }
  validates :custom_scope, length: { maximum: 256 }
  validates :custom_uid_field, length: { maximum: 40 }
  validates :custom_email_field, length: { maximum: 40 }
  validates :custom_firstname_field, length: { maximum: 30 }
  validates :custom_lastname_field, length: { maximum: 30 }
  validates :custom_logout_endpoint, length: { maximum: 80 }
  validates :validate_user_roles, length: { maximum: 40 }
  validates :url_parameters, length: { maximum: 128 }, if: proc { has_attribute?(:url_parameters) }
  validates :button_text, length: { maximum: 40 }, if: proc { has_attribute?(:button_text) }
  validate :validate_role_name_lists, if: proc { has_attribute?(:login_role_name) }

  ROLE_VALUE_MAX_LENGTH = 1024
  GROUP_NAME_MAX_LENGTH = 255
  DEFAULT_LOGIN_ROLE = 'user'
  DEFAULT_ADMIN_ROLE = 'admin'

  scope :sorted, -> { order(:position) }

  # Percent-decode a claim or setting value. '+' is left alone (URN-safe).
  def self.decode_role_value(value)
    decoded = value.to_s.gsub(/%([0-9A-Fa-f]{2})/) { [Regexp.last_match(1).to_i(16)].pack('C') }
    decoded.force_encoding(Encoding::UTF_8)
    unless decoded.valid_encoding?
      decoded = decoded.encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
    end
    decoded
  end

  def self.parse_role_list(raw, default: nil)
    list = raw.to_s.split(/[,\n]/).map { |part| decode_role_value(part.strip) }.compact_blank
    list.presence || Array(default)
  end

  # Same comparison Redmine uses for Group.named and lastname uniqueness: strip, then case-insensitive.
  def self.group_name_key(value)
    decode_role_value(value).strip.downcase
  end

  def login_role_values
    raw = has_attribute?(:login_role_name) ? login_role_name : nil
    self.class.parse_role_list(raw, default: DEFAULT_LOGIN_ROLE)
  end

  def admin_role_values
    raw = has_attribute?(:admin_role_name) ? admin_role_name : nil
    self.class.parse_role_list(raw, default: DEFAULT_ADMIN_ROLE)
  end

  def reserved_role_values
    login_role_values | admin_role_values
  end

  def extract_roles(user_info)
    key = validate_user_roles.to_s.strip
    return [] if key.blank?

    pattern = /^#{Regexp.escape(key)}(\.\d+)?$/
    Array(user_info).each_with_object([]) do |(k, v), acc|
      acc << self.class.decode_role_value(v) if k.to_s.match?(pattern)
    end
  end

  def matching_groups(role_names)
    wanted = Array(role_names).map { |name| self.class.group_name_key(name) }.reject(&:blank?)
    Group.givable.select { |group| wanted.include?(self.class.group_name_key(group.lastname)) }
  end

  # Claim values that should become groups: reserved login/admin values are dropped with the same
  # strip + case-insensitive key Redmine uses, so "Viewer" does not also create a group named viewer.
  def group_role_names(roles)
    reserved = reserved_role_values.map { |name| self.class.group_name_key(name) }
    Array(roles).reject { |name| reserved.include?(self.class.group_name_key(name)) }
  end

  # Existing groups always, missing ones only when create_missing_groups is on.
  # group_exclude_list blocks creation only; an already existing excluded group is still assigned.
  def sync_groups(role_names)
    wanted = Array(role_names).filter_map { |name| self.class.decode_role_value(name).strip.presence }.uniq
    groups = matching_groups(wanted)
    return groups unless create_missing_groups_enabled?

    found = groups.map { |group| self.class.group_name_key(group.lastname) }
    excluded = excluded_group_values.map { |name| self.class.group_name_key(name) }
    wanted.each do |name|
      key = self.class.group_name_key(name)
      next if found.include?(key) || excluded.include?(key)

      created = create_group_for_role(name)
      next unless created

      groups << created
      found << key
    end
    groups
  end

  def excluded_group_values
    return [] unless has_attribute?(:group_exclude_list)

    self.class.parse_role_list(group_exclude_list)
  end

  def create_missing_groups_enabled?
    has_attribute?(:create_missing_groups) && create_missing_groups?
  end

  def role_grants_login?(roles)
    roles.intersect?(login_role_values) || roles.intersect?(admin_role_values)
  end

  def role_grants_admin?(roles)
    roles.intersect?(admin_role_values)
  end

  def update_from_parameters(params)
    self.oauth_name = params['oauth_name']
    self.site = params['site']
    self.client_id = params['client_id']
    self.client_secret = Redmine::Ciphering.encrypt_text(params['client_secret'])
    self.tenant_id = params['tenant_id']
    self.custom_name = params['custom_name']
    self.custom_auth_endpoint = params['custom_auth_endpoint']
    self.custom_token_endpoint = params['custom_token_endpoint']
    self.custom_profile_endpoint = params['custom_profile_endpoint']
    self.custom_scope = params['custom_scope']
    self.custom_uid_field = params['custom_uid_field']
    self.custom_email_field = params['custom_email_field']
    self.button_color_enabled = params['button_color_enabled'] || true
    self.button_color = params['button_color']
    self.button_icon = params['button_icon']
    self.custom_firstname_field = params['custom_firstname_field']
    self.custom_lastname_field = params['custom_lastname_field']
    self.custom_logout_endpoint = params['custom_logout_endpoint']
    self.validate_user_roles = params['validate_user_roles']
    self.enable_group_roles = params['enable_group_roles']
    self.login_role_name = params['login_role_name'] if has_attribute?(:login_role_name)
    self.admin_role_name = params['admin_role_name'] if has_attribute?(:admin_role_name)
    self.create_missing_groups = params['create_missing_groups'] if has_attribute?(:create_missing_groups)
    self.group_exclude_list = params['group_exclude_list'] if has_attribute?(:group_exclude_list)
    self.oauth_version = params['oauth_version']
    self.identify_user_by = params['identify_user_by']
    self.imap = params['imap']
    self.url_parameters = params['url_parameters']
    self.button_text = params['button_text']
    # Reset IMAP by other providers
    OauthProvider.where.not(id: id).where(imap: true).update(imap: false) if imap
  end

  private

  def validate_role_name_lists
    raws = [login_role_name, admin_role_name]
    raws << group_exclude_list if has_attribute?(:group_exclude_list)
    raws.each do |raw|
      self.class.parse_role_list(raw).each do |role|
        next unless role.bytesize > ROLE_VALUE_MAX_LENGTH

        errors.add(:base, "Role value exceeds #{ROLE_VALUE_MAX_LENGTH} bytes")
      end
    end
  end

  def create_group_for_role(name)
    name = self.class.decode_role_value(name).strip
    return if name.blank?
    if name.length > GROUP_NAME_MAX_LENGTH
      Rails.logger.info("OAuth skipped group longer than #{GROUP_NAME_MAX_LENGTH}: #{name}")
      return
    end

    existing = find_givable_group(name)
    return existing if existing

    Group.create!(lastname: name)
  rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique => e
    Rails.logger.error("OAuth group create failed for #{name}: #{e.message}")
    find_givable_group(name)
  end

  def find_givable_group(name)
    scope = Group.givable
    if scope.respond_to?(:named)
      scope.named(name).first
    else
      scope.where('LOWER(lastname) = LOWER(?)', name).first
    end
  end
end
