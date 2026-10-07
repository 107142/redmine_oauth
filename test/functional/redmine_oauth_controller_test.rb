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

require File.expand_path('../../integration_test', __FILE__)

# OAuth controller test
class RedmineOauthControllerTest < RedmineOAuth::Test::IntegrationTest
  include Redmine::I18n

  def setup
    super
    @keylock_provider = OauthProvider.find(1)
    @invalid_provider = OauthProvider.find(2)
    @jsmith = User.find_by(login: 'jsmith')
    @oauth_provider = OauthProvider.find(1)
  end

  def test_oauth
    get "/oauth?oauth_provider=#{@invalid_provider.id}"
    assert_redirected_to signin_path
    assert_equal l(:oauth_invalid_provider), flash[:error]
  end

  def test_oauth_url_concatenation_for_keycloak
    get "/oauth?oauth_provider=#{@keylock_provider.id}"
    assert_redirected_to(%r{^https://example\.com/sso/realms/redmine/protocol/})
  end

  def test_oauth_keeps_transient_state_out_of_session
    get "/oauth?oauth_provider=#{@keylock_provider.id}&back_url=/my/account"

    assert_nil session[:oauth_provider]
    assert_nil session[:back_url]
    assert_nil session[:oauth_csrf_token]
    assert_nil session[:code_verifier]
    assert cookies[:redmine_oauth_request_state].present?
  end

  def test_oauth_callback_accepts_state_from_request_cookie
    get "/oauth?oauth_provider=#{@keylock_provider.id}"
    state = URI.decode_www_form(URI.parse(response.location).query).to_h.fetch('state')

    get "/oauth2callback?state=#{state}&code=unused"

    assert_response :found
  end

  def test_oauth_callback_csrf
    get '/oauth2callback'
    assert_response :unprocessable_content
  end

  def test_update_user_login
    with_settings plugin_redmine_oauth: { 'update_login' => '0' } do
      RedmineOauthController.update_user @jsmith, 'login', 'email@example.com', 'firstname', 'lastname'
      assert_equal 'jsmith', @jsmith.login
    end
    with_settings plugin_redmine_oauth: { 'update_login' => '1' } do
      RedmineOauthController.update_user @jsmith, 'login', 'email@example.com', 'firstname', 'lastname'
      assert_equal 'login', @jsmith.login
    end
  end

  def test_update_user_email
    with_settings plugin_redmine_oauth: { 'update_email' => '0' } do
      RedmineOauthController.update_user @jsmith, 'login', 'email@example.com', 'firstname', 'lastname'
      assert_equal 'jsmith@somenet.foo', @jsmith.mail
    end
    with_settings plugin_redmine_oauth: { 'update_email' => '1' } do
      RedmineOauthController.update_user @jsmith, 'login', 'email@example.com', 'firstname', 'lastname'
      assert_equal 'email@example.com', @jsmith.mail
    end
  end

  def test_update_firstname
    with_settings plugin_redmine_oauth: { 'update_firstname' => '0' } do
      RedmineOauthController.update_user @jsmith, 'login', 'email@example.com', 'firstname', 'lastname'
      assert_equal 'John', @jsmith.firstname
    end
    with_settings plugin_redmine_oauth: { 'update_firstname' => '1' } do
      RedmineOauthController.update_user @jsmith, 'login', 'email@example.com', 'firstname', 'lastname'
      assert_equal 'firstname', @jsmith.firstname
    end
  end

  def test_update_lastname
    with_settings plugin_redmine_oauth: { 'update_lastname' => '0' } do
      RedmineOauthController.update_user @jsmith, 'login', 'email@example.com', 'firstname', 'lastname'
      assert_equal 'Smith', @jsmith.lastname
    end
    with_settings plugin_redmine_oauth: { 'update_lastname' => '1' } do
      RedmineOauthController.update_user @jsmith, 'login', 'email@example.com', 'firstname', 'lastname'
      assert_equal 'lastname', @jsmith.lastname
    end
  end

  def test_get_firstname
    info = {
      'name' => 'John Smith'
    }
    assert_equal 'John', RedmineOauthController.get_firstname(info, @oauth_provider)
    info = {
      'name' => 'Jan de Jong'
    }
    assert_equal 'Jan', RedmineOauthController.get_firstname(info, @oauth_provider)
  end

  def test_get_lastname
    info = {
      'name' => 'John Smith'
    }
    assert_equal 'Smith', RedmineOauthController.get_lastname(info, @oauth_provider)
    info = {
      'name' => 'Jan de Jong'
    }
    assert_equal 'de Jong', RedmineOauthController.get_lastname(info, @oauth_provider)
  end

  def test_decode_role_value_percent_decodes_but_keeps_plus
    assert_equal 'masaryk university', OauthProvider.decode_role_value('masaryk%20university')
    assert_equal 'masaryk university', OauthProvider.decode_role_value('masaryk university')
    assert_equal 'a+b', OauthProvider.decode_role_value('a+b')
    assert_equal 'res:admin', OauthProvider.decode_role_value('res%3Aadmin')
  end

  def test_parse_role_list_comma_and_newline
    list = OauthProvider.parse_role_list(
      'urn:geant:muni.cz:res:viewer#idm.ics.muni.cz, urn:geant:muni.cz:res:admin#idm.ics.muni.cz',
      default: 'user'
    )
    assert_equal 2, list.size
    assert_includes list, 'urn:geant:muni.cz:res:viewer#idm.ics.muni.cz'
    list = OauthProvider.parse_role_list("one\n two%20two \n", default: 'user')
    assert_equal ['one', 'two two'], list
    assert_equal ['user'], OauthProvider.parse_role_list('', default: 'user')
  end

  def test_extract_roles_flattens_and_decodes_entitlements
    @oauth_provider.validate_user_roles = 'eduperson_entitlement'
    @oauth_provider.login_role_name = 'urn:geant:muni.cz:res:viewer#idm.ics.muni.cz'
    @oauth_provider.admin_role_name = 'urn:geant:muni.cz:res:admin#idm.ics.muni.cz'
    user_info = {
      'eduperson_entitlement.0' => 'urn:geant:muni.cz:res:viewer#idm.ics.muni.cz',
      'eduperson_entitlement.1' => 'urn:geant:muni.cz:res:admin#idm.ics.muni.cz',
      'eduperson_entitlement.2' => 'urn:geant:muni.cz:group:MU:ff-cit-sys#idm.ics.muni.cz',
      'email' => 'someone@muni.cz'
    }
    roles = @oauth_provider.extract_roles(user_info)
    assert_equal 3, roles.size
    assert @oauth_provider.role_grants_login?(roles)
    assert @oauth_provider.role_grants_admin?(roles)
    leftover = roles - @oauth_provider.reserved_role_values
    assert_equal ['urn:geant:muni.cz:group:MU:ff-cit-sys#idm.ics.muni.cz'], leftover
  end

  def test_encoded_claim_matches_decoded_login_role
    @oauth_provider.validate_user_roles = 'eduperson_entitlement'
    @oauth_provider.login_role_name = 'urn:geant:muni.cz:group:MU:workplaces-employees:masaryk university'
    @oauth_provider.admin_role_name = 'urn:geant:muni.cz:res:admin#idm.ics.muni.cz'
    roles = @oauth_provider.extract_roles(
      'eduperson_entitlement.0' =>
        'urn:geant:muni.cz:group:MU:workplaces-employees:masaryk%20university'
    )
    assert @oauth_provider.role_grants_login?(roles)
    assert_not @oauth_provider.role_grants_admin?(roles)
  end

  def test_extract_roles_denies_without_login_or_admin_value
    @oauth_provider.validate_user_roles = 'eduperson_entitlement'
    @oauth_provider.login_role_name = 'urn:geant:muni.cz:res:viewer#idm.ics.muni.cz'
    @oauth_provider.admin_role_name = 'urn:geant:muni.cz:res:admin#idm.ics.muni.cz'
    roles = @oauth_provider.extract_roles(
      'eduperson_entitlement.0' => 'urn:geant:muni.cz:group:MU:ff-cit-sys#idm.ics.muni.cz'
    )
    assert_not @oauth_provider.role_grants_login?(roles)
    assert_not @oauth_provider.role_grants_admin?(roles)
  end

  def test_default_user_admin_literals_still_work
    @oauth_provider.validate_user_roles = 'roles'
    @oauth_provider.login_role_name = nil
    @oauth_provider.admin_role_name = nil
    roles = @oauth_provider.extract_roles('roles.0' => 'user', 'roles.1' => 'admin')
    assert @oauth_provider.role_grants_login?(roles)
    assert @oauth_provider.role_grants_admin?(roles)
    assert_equal [], roles - @oauth_provider.reserved_role_values
  end

  def test_matching_groups_decodes_both_sides
    group = Group.create!(lastname: 'ff cit sys')
    matched = @oauth_provider.matching_groups(['ff%20cit%20sys', 'missing'])
    assert_equal [group.id], matched.map(&:id)
  ensure
    group&.destroy
  end

  def test_sync_groups_does_not_create_unless_enabled
    assert_no_difference 'Group.count' do
      matched = @oauth_provider.sync_groups(['brand new group'])
      assert_empty matched
    end
  end

  def test_sync_groups_creates_missing_and_skips_exclude_list
    @oauth_provider.create_missing_groups = true
    @oauth_provider.group_exclude_list = "keep%20out\nalready here"
    existing = Group.create!(lastname: 'already here')
    created = nil
    assert_difference 'Group.count', +1 do
      matched = @oauth_provider.sync_groups(['new faculty', 'keep out', 'already%20here'])
      assert_includes matched.map(&:lastname), 'new faculty'
      assert_includes matched.map(&:id), existing.id
      assert_not_includes matched.map(&:lastname), 'keep out'
      created = matched.detect { |group| group.lastname == 'new faculty' }
    end
  ensure
    created&.destroy
    existing&.destroy
  end

  def test_sync_groups_skips_names_longer_than_redmine_limit
    @oauth_provider.create_missing_groups = true
    long_name = 'g' * 256
    assert_no_difference 'Group.count' do
      assert_empty @oauth_provider.sync_groups([long_name])
    end
  end
end

