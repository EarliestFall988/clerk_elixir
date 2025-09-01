defmodule Clerk.Utilities do

  @moduledoc """
  Utility functions useful to the Clerk authentication system and authentication in general
  """

  @spec get_token_from_header(Plug.Conn.t()) :: String.t() | nil
  @doc """
  Get the authorization token from the request headers.


  ## Examples

      iex> conn = Plug.Conn.put_req_header(%Plug.Conn{}, "authorization", "Bearer my_token")
      iex> Clerk.Utilities.get_token_from_header(conn)
      "my_token"

  """
  def get_token_from_header(conn) do
    conn
    |> Plug.Conn.get_req_header("authorization")
    |> List.first()
    |> case do
      nil -> nil
      header -> String.replace(header, "Bearer ", "")
    end
  end
end
