defmodule Clerk.AuthenticationPlug do
  @moduledoc """
  Plug for authenticating requests.
  """

  @behaviour Plug

  @table_name :clerk_cache
  @cache_ttl 3600

  @doc """
  Authenticates the request.
  """
  def init(opts) do

    if :ets.info(@table_name) === :undefined do
      :ets.new(:clerk_cache, [:set, :public, :named_table])
    end

    opts
  end

  def call(conn, opts) do

    session_key = Keyword.get(opts, :session_key, "__session")

    case check_cache(conn, session_key, @cache_ttl) do
      :cache_miss ->
        # IO.inspect({"CACHE MISS"})
        get_from_clerk(conn, session_key, nil)

      :cache_expired ->
        # IO.inspect({"CACHE EXPIRED"})
        get_from_clerk(conn, session_key, nil)

      {:grace, session, user} ->
        get_from_clerk(conn, session_key, {session, user})

      {:ok, session, user} ->
        # IO.inspect({"FOUND DATA FROM CACHE"})

        conn
        |> Plug.Conn.assign(:clerk_session, session)
        |> Plug.Conn.assign(:current_user, user)
    end

  end

  defp get_from_clerk(conn, session_key, grace_data) do

    with {:ok, token} <- get_auth_token(conn, session_key),
    {:ok, %{"sub" => user_id} = session} <- Clerk.Session.verify_and_validate(token),
    {:ok, user} <- Clerk.User.get(user_id) do


      :ets.insert(@table_name, {token, {session, user, System.os_time(:seconds)}})

      conn
      |> Plug.Conn.assign(:clerk_session, session)
      |> Plug.Conn.assign(:current_user, user)

    else
        {:err, :timeout} ->

        if(grace_data != nil) do
          {session, user } = grace_data
          conn
          |> Plug.Conn.assign(:clerk_session, session)
          |> Plug.Conn.assign(:current_user, user)
        else
          conn
          |> Plug.Conn.send_resp(503, "Authentication services unavailable.") # Either Clerk is down or Clerk is throttling your requests.
          |> Plug.Conn.halt()
        end
      _ ->

        if(grace_data != nil) do
          {session, user } = grace_data
          conn
          |> Plug.Conn.assign(:clerk_session, session)
          |> Plug.Conn.assign(:current_user, user)
        else
          conn
          |> Plug.Conn.send_resp(401, "Unauthorized")
          |> Plug.Conn.halt()
        end
    end
  end

  defp get_auth_token(conn, session_key) do
    auth_header = get_token_from_header(conn)

    if auth_header do # if the auth header token is present ...
      {:ok, auth_header}
    else
      case Map.fetch(conn.req_cookies, session_key) do # otherwise grab the cookie
        {:ok, session} -> {:ok, session}
        _ -> {:error, :unauthorized}
      end
    end
  end

  defp get_token_from_header(conn) do
    conn
    |> Plug.Conn.get_req_header("authorization")
    |> List.first()
    |> case do
      nil -> nil
      header -> String.replace(header, "Bearer ", "")
    end
  end


  defp check_cache(conn, session_key, cache_ttl) do

    token_result = get_auth_token(conn, session_key)

    case token_result do
      {:ok, token } ->
          case :ets.lookup(@table_name, token) do
            [{^token, data}] ->
              # IO.inspect {:cached_data_found, data}
              validate_token(data, cache_ttl)
            [] -> :cache_miss
          end
      _ ->
        :cache_miss
    end
  end


  defp validate_token({session, user, timestamp}, cache_ttl) do

    current_time = System.os_time(:second)
    session_expiry = Map.get(session, "exp", current_time + 1)

    cond do
        current_time < session_expiry && current_time - timestamp < cache_ttl ->
          {:ok, session, user}
        current_time < session_expiry && current_time - timestamp < cache_ttl + 300 ->
          {:grace, session, user}
        true ->
          :cache_expired
    end
  end
end




# {:ok, %{
#   "azp" => "http://localhost:5173",
#   "clerk_id" => "user_2wmkpgWWq4mRYo6obGuK1oWt5DN",
#   email" => true,
#   "exp" => 1754848897,
#   "full_name" => "Taylor Howell",
#   "fva" => [1364, -1],
#   "has_image" => true,
#   "iat" => 1754848837,
#   "image_url" => "https://img.clerk.com/eyJ0eXBlIjoicHJveHkiLCJzcmMiOiJodHRwczovL2ltYWdlcy5jbGVyay5kZXYvb2F1dGhfZ29vZ2xlL2ltZ18yd21rcGhTR0pTcldyd05POVdlVkd0YW5RNWgifQ",
#   "iss" => "https://present-bream-83.clerk.accounts.dev",
#   "jti" => "1216f517a5ecfaac7b9a",
#   "nbf" => 1754848827,
#   "sid" => "sess_313yIaIAvigtlJ55XezCnHdzvhf",
#   "sub" => "user_2wmkpgWWq4mRYo6obGuK1oWt5DN",
#   "v" => 2, "verified" => true},
#    %{
#       "verification_attempts_remaining" => 5,
#       "mfa_disabled_at" => nil,
#       "delete_self_enabled" => false,
#       "public_metadata" => %{},
#       "primary_phone_number_id" => nil,
#       "enterprise_accounts" => [],
#       "external_accounts" => [
#         %{
#         "approved_scopes" => "email https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid profile",
#         "avatar_url" => "https://lh3.googleusercontent.com/a/ACg8ocI5I98qKTHOaIdGu4CRgBo_H-pIzyFKbbC4ImrzUsy4zDy8Op3W=s1000-c",
#         "created_at" => 1746654312512,
#         "email_address" => "howelltaylor747@gmail.com",
#         "external_account_id" => "eac_2wmkogFik2L3hqwAUs6photZqqc",
#         "family_name" => "Howell",
#         "first_name" => "Taylor",
#         "given_name" => "Taylor",
#         "google_id" => "107867656488342353433",
#         "id" => "idn_2wmkoi1BvZFVsIIQcejZ1lWAbwJ",
#         "identification_id" => "idn_2wmkoi1BvZFVsIIQcejZ1lWAbwJ",
#         "image_url" => "https://img.clerk.com/eyJ0eXBlIjoicHJveHkiLCJzcmMiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NJNUk5OHFLVEhPYUlkR3U0Q1JnQm9fSC1wSXp5RktiYkM0SW1yelVzeTR6RHk4T3AzVz1zMTAwMC1jIiwicyI6Iml1SXdpUW1oQVQ2UE13NnFubnFmMjhybWUxVmhwNmlDeVhjMEtYcnpQMFkifQ",
#         "label" => nil,
#         "last_name" => "Howell",
#         "object" => "google_account",
#         "picture" => "https://lh3.googleusercontent.com/a/ACg8ocI5I98qKTHOaIdGu4CRgBo_H-pIzyFKbbC4ImrzUsy4zDy8Op3W=s1000-c",
#         "provider" => "oauth_google",
#         "provider_user_id" => "107867656488342353433",
#         "public_metadata" => %{},
#         "updated_at" => 1754766971677,
#         "username" => "",
#         "verification" => %{"attempts" => nil, "expire_at" => 1746654906402,
#         "object" => "verification_oauth",
#         "status" => "verified",
#         "strategy" => "oauth_google"
#         }
#       }],
#       "locked" => false,
#       "create_organization_enabled" => true,
#       "last_active_at" => 1754842146998,
#       "profile_image_url" => "https://images.clerk.dev/oauth_google/img_2wmkphSGJSrWrwNO9WeVGtanQ5h",
#       "password_enabled" => false,
#       "backup_code_enabled" => false,
#       "two_factor_enabled" => false,
#       "updated_at" => 1754766971754,
#       "web3_wallets" => [],
#       "has_image" => true,
#       "id" => "user_2wmkpgWWq4mRYo6obGuK1oWt5DN",
#       "totp_enabled" => false,
#       "primary_email_address_id" => "idn_2wmkog9TWWGAe9HyZ8aNzlzQ9sX",
#       "private_metadata" => %{},
#       "legal_accepted_at" => nil,
#       "primary_web3_wallet_id" => nil,
#       "passkeys" => [],
#       "unsafe_metadata" => %{},
#       "object" => "user",
#        "external_id" => nil,
#        "image_url" => "https://img.clerk.com/eyJ0eXBlIjoicHJveHkiLCJzcmMiOiJodHRwczovL2ltYWdlcy5jbGVyay5kZXYvb2F1dGhfZ29vZ2xlL2ltZ18yd21rcGhTR0pTcldyd05POVdlVkd0YW5RNWgifQ", "email_addresses" => [%{"created_at" => 1746654312518, "email_address" => "howelltaylor747@gmail.com", "id" => "idn_2wmkog9TWWGAe9HyZ8aNzlzQ9sX", "linked_to" => [%{"id" => "idn_2wmkoi1BvZFVsIIQcejZ1lWAbwJ", "type" => "oauth_google"}], "matches_sso_connection" => false, "object" => "email_address", "reserved" => false, "updated_at" => 1746654320738, "verification" => %{"attempts" => nil, "expire_at" => nil, "object" => "verification_from_oauth", "status" => "verified", "strategy" => "from_oauth_google"}}], "phone_numbers" => [], "last_sign_in_at" => 1754766971713, "last_name" => "Howell", "mfa_enabled_at" => nil, "username" => nil, "lockout_expires_in_seconds" => nil, "first_name" => "Taylor", "created_at" => 1746654320724, "saml_accounts" => [], "banned" => false}}
