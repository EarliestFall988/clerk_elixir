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

  def get_table_name, do: @table_name

  def lookup_token(token) do
    IO.inspect({:lookup, token})
    :ets.lookup(@table_name, token)
  end

  def insert(token, session, user) do
    time = System.os_time(:seconds)
    IO.inspect({:inserting_data, session, token})
    :ets.insert(@table_name, {token, {session, user, time}})
  end
end
