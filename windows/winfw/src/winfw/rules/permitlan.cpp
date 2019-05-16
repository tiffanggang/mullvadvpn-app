#include "stdafx.h"
#include "permitlan.h"
#include "winfw/mullvadguids.h"
#include "libwfp/filterbuilder.h"
#include "libwfp/conditionbuilder.h"
#include "libwfp/ipaddress.h"
#include "libwfp/conditions/conditionip.h"

using namespace wfp::conditions;

namespace rules
{

bool PermitLan::apply(IObjectInstaller &objectInstaller)
{
	return applyIpv4(objectInstaller) && applyIpv6(objectInstaller);
}

bool PermitLan::applyIpv4(IObjectInstaller &objectInstaller) const
{
	wfp::FilterBuilder filterBuilder;

	//
	// #1 locally-initiated traffic
	//

	filterBuilder
		.key(MullvadGuids::FilterPermitLan_Outbound_Ipv4())
		.name(L"Permit locally-initiated LAN traffic")
		.description(L"This filter is part of a rule that permits LAN traffic")
		.provider(MullvadGuids::Provider())
		.layer(FWPM_LAYER_ALE_AUTH_CONNECT_V4)
		.sublayer(MullvadGuids::SublayerWhitelist())
		.weight(wfp::FilterBuilder::WeightClass::Max)
		.permit();

	wfp::ConditionBuilder conditionBuilder(FWPM_LAYER_ALE_AUTH_CONNECT_V4);

	conditionBuilder.add_condition(ConditionIp::Remote(wfp::IpAddress::Literal({ 10, 0, 0, 0 }), uint8_t(8)));
	conditionBuilder.add_condition(ConditionIp::Remote(wfp::IpAddress::Literal({ 172, 16, 0, 0 }), uint8_t(12)));
	conditionBuilder.add_condition(ConditionIp::Remote(wfp::IpAddress::Literal({ 192, 168, 0, 0 }), uint8_t(16)));
	conditionBuilder.add_condition(ConditionIp::Remote(wfp::IpAddress::Literal({ 169, 254, 0, 0 }), uint8_t(16)));

	if (!objectInstaller.addFilter(filterBuilder, conditionBuilder))
	{
		return false;
	}

	//
	// #2 LAN to multicast
	//

	filterBuilder
		.key(MullvadGuids::FilterPermitLan_Outbound_Multicast_Ipv4())
		.name(L"Permit locally-initiated multicast traffic");

	conditionBuilder.reset();

	// Local subnet multicast.
	conditionBuilder.add_condition(ConditionIp::Remote(wfp::IpAddress::Literal({ 224, 0, 0, 0 }), uint8_t(24)));

	// Simple Service Discovery Protocol (SSDP) address.
	conditionBuilder.add_condition(ConditionIp::Remote(wfp::IpAddress::Literal({ 239, 255, 255, 250 }), uint8_t(32)));

	// mDNS Service Discovery address.
	conditionBuilder.add_condition(ConditionIp::Remote(wfp::IpAddress::Literal({ 239, 255, 255, 251 }), uint8_t(32)));

	return objectInstaller.addFilter(filterBuilder, conditionBuilder);
}

bool PermitLan::applyIpv6(IObjectInstaller &objectInstaller) const
{
	wfp::FilterBuilder filterBuilder;

	//
	// #1 locally-initiated traffic
	//

	filterBuilder
		.key(MullvadGuids::FilterPermitLan_Outbound_Ipv6())
		.name(L"Permit locally-initiated LAN traffic")
		.description(L"This filter is part of a rule that permits LAN traffic")
		.provider(MullvadGuids::Provider())
		.layer(FWPM_LAYER_ALE_AUTH_CONNECT_V6)
		.sublayer(MullvadGuids::SublayerWhitelist())
		.weight(wfp::FilterBuilder::WeightClass::Max)
		.permit();

	wfp::ConditionBuilder conditionBuilder(FWPM_LAYER_ALE_AUTH_CONNECT_V6);

	wfp::IpAddress::Literal6 fe80 { 0xFE80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	conditionBuilder.add_condition(ConditionIp::Remote(fe80, uint8_t(10)));

	if (!objectInstaller.addFilter(filterBuilder, conditionBuilder))
	{
		return false;
	}

	//
	// #2 LAN to multicast
	//

	filterBuilder
		.key(MullvadGuids::FilterPermitLan_Outbound_Multicast_Ipv6())
		.name(L"Permit locally-initiated IPv6 multicast traffic");

	conditionBuilder.reset();

	wfp::IpAddress::Literal6 linkLocal{ 0xFF02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	wfp::IpAddress::Literal6 siteLocal{ 0xFF05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	conditionBuilder.add_condition(ConditionIp::Remote(linkLocal, uint8_t(16)));
	conditionBuilder.add_condition(ConditionIp::Remote(siteLocal, uint8_t(16)));

	return objectInstaller.addFilter(filterBuilder, conditionBuilder);
}

}
