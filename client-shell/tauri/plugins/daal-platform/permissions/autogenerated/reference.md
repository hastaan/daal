## Default Permission

Default permission set for the daal-platform plugin. Grants the three
commands the Daal frontend needs to drive the Android VpnService and
TUN-fd handoff. Desktop hosts get the same surface as no-op handlers
so the same frontend bindings work everywhere.

#### This default permission set includes the following:

- `allow-vpn-start`
- `allow-vpn-stop`
- `allow-vpn-status`

## Permission Table

<table>
<tr>
<th>Identifier</th>
<th>Description</th>
</tr>


<tr>
<td>

`daal-platform:allow-vpn-start`

</td>
<td>

Enables the vpn_start command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`daal-platform:deny-vpn-start`

</td>
<td>

Denies the vpn_start command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`daal-platform:allow-vpn-status`

</td>
<td>

Enables the vpn_status command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`daal-platform:deny-vpn-status`

</td>
<td>

Denies the vpn_status command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`daal-platform:allow-vpn-stop`

</td>
<td>

Enables the vpn_stop command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`daal-platform:deny-vpn-stop`

</td>
<td>

Denies the vpn_stop command without any pre-configured scope.

</td>
</tr>
</table>
