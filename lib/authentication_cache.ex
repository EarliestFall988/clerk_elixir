defmodule Clerk.AuthenticationCache do
  use GenServer

  @table_name :clerk_cache

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init(_) do
    :ets.new(@table_name, [:set, :public, :named_table])
    {:ok, %{}}
  end

  @doc """

  Fetch the table name for more interaction with the clerk authentication cache
  """
  def get_table_name, do: @table_name

  @doc """

  Lookup a token to see if has been cached

  """
  def lookup_token(token) do
    IO.inspect({:lookup, token})
    :ets.lookup(@table_name, token)
  end

  @doc """

  Insert a new session into the cache
  """
  def insert(token, session, user) do
    time = System.os_time(:seconds)
    IO.inspect({:inserting_data, session, token})
    :ets.insert(@table_name, {token, {session, user, time}})
  end

  @doc """

  Removes an existing token in the session cache.

  This is helpful for scenarios when someone is banned, or when they log out - here you can activate a webhook and trigger a logout
  """
  def remove(token), do: :ets.delete(@table_name, token)

end
