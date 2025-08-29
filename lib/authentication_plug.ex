defmodule Clerk.AuthenticationPlug do
  @moduledoc """
  Plug for authenticating requests.
  """
alias Clerk.AuthenticationCache


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
        IO.puts("[auth]: cache miss")
        get_from_clerk(conn, session_key, nil)

      :cache_expired ->
        IO.puts("[auth]: cache expired")
        get_from_clerk(conn, session_key, nil)

      {:grace, session, user} ->
        get_from_clerk(conn, session_key, {session, user})

      {:ok, session, user} ->
        IO.puts("[auth]: cache hit")

        conn
        |> Plug.Conn.assign(:clerk_session, session)
        |> Plug.Conn.assign(:current_user, user)
    end

  end

  defp get_from_clerk(conn, session_key, grace_data) do

    # {:ok, token} = get_auth_token(conn, session_key)


    # IO.inspect {:token, token}
    # {:ok, session} = Clerk.Session.verify_and_validate(token)


    # IO.inspect {:get_clerk_from, {token, session}}

    with {:ok, token} <- get_auth_token(conn, session_key),
    {:ok, %{"sub" => user_id} = session} <- Clerk.Session.verify_and_validate(token),
    {:ok, user} <- Clerk.User.get(user_id) do


      # :ets.insert(@table_name, {token, {session, user, System.os_time(:seconds)}})
      AuthenticationCache.insert(token, session, user)

      conn
      |> Plug.Conn.assign(:clerk_session, session)
      |> Plug.Conn.assign(:current_user, user)

    else

      {:error, :unauthorized} ->

        if(grace_data != nil) do
          {session, user} = grace_data
          conn
          |> Plug.Conn.assign(:clerk_session, session)
          |> Plug.Conn.assign(:current_user, user)
        else
          conn
          |> Plug.Conn.send_resp(408, "Unauthorized") # Either Clerk is down or Clerk is throttling your requests.
          |> Plug.Conn.halt()
        end

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

        # IO.inspect(:err, x)

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

        # :ets.lookup(@table_name, token)
          case AuthenticationCache.lookup_token(token) do
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
