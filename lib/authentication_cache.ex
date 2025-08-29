defmodule Clerk.AuthenticationCache do
  use GenServer

  @table_name :clerk_cache

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init(_) do
    :ets.new(@table_name, [:set, :protected, :named_table])
    {:ok, %{}}
  end

  @doc """

  Fetch the table name for more interaction with the clerk authentication cache
  """
  def get_table_name, do: @table_name

  @doc """

  Lookup a token to see if has been cached

  """
  def lookup_token(token) when is_binary(token) do
    # IO.inspect({:lookup, token})
    :ets.lookup(@table_name, token)
  end

  @doc """

  Insert a new session into the cache
  """
  def insert(token, session, user) when is_binary(token) do
    time = System.os_time(:second)
    :ets.insert(@table_name, {token, %{session: session, user: user, time: time, group_id: nil}})
  end


  @doc """

  Set the group ID for a given token in the cache. It does not validate the group_id.

  ## Examples

      iex> Clerk.AuthenticationCache.set_group_id("some_token", "new_group_id")
      :ok

      iex> Clerk.AuthenticationCache.set_group_id("non_existent_token", "new_group_id")
      :error

  """

  def set_group_id(token, new_group_id) when is_binary(new_group_id) do

    case lookup_token(token) do
      [{^token, data}] ->
        :ets.insert(@table_name, {token, %{data | group_id: new_group_id}})
        :ok

      _ ->
        :error
    end
  end

  @doc """

  Get the group ID for a given token.

  ## Examples

      iex> Clerk.AuthenticationCache.get_group_id("some_token")
      {:ok, "some_group_id"}

      iex> Clerk.AuthenticationCache.get_group_id("non_existent_token")
      :error

  """
  def get_group_id(token) do
    case lookup_token(token) do
      [{^token, data}] -> {:ok, data.group_id}
      _ -> :error
    end
  end

  @doc """

  Removes an existing token in the session cache.

  This is helpful for scenarios when someone is banned, or when they log out - here you can activate a webhook and trigger a logout
  """
  def remove(token), do: :ets.delete(@table_name, token)

end
