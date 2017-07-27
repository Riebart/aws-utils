#!/usr/bin/env python
"""
Use the EC2 API via boto3 to find the best price for an instance type (or types) and products (Linux,
Windows, etc...) across regions.
"""

import sys
import json
import urllib2
import argparse
import calendar
import threading
from datetime import datetime, timedelta, tzinfo
import pytz
import dateutil.parser
import boto3


def nonempty_list(arg):
    if len(arg) > 0:
        return arg
    else:
        raise ValueError("Must be at least one instance type")


def tiered_dict(itemlist, keylist):
    """
    Given a list of dictionaries and a list of keys, each dictionary in the first list having all of
    the keys from the second list defined, create a tiered grouping of the items in the first based
    on the keys from the second list.
    """
    result = dict()
    if len(keylist) == 0:
        raise ValueError("Length of key list must be at least 1")
    elif len(keylist) == 1:
        key = keylist[0]
        for item in itemlist:
            if item[key] not in result:
                result[item[key]] = []
            result[item[key]].append(item)
    else:
        for item in itemlist:
            part = result
            for key in keylist[:-1]:
                if item[key] not in part:
                    part[item[key]] = dict()
                part = part[item[key]]
            if item[keylist[-1]] not in part:
                part[item[keylist[-1]]] = []
            part[item[keylist[-1]]].append(item)
    return result


def get_region_prices(region, pargs, price_list):
    region_prices = []
    ec2r = boto3.client("ec2", region_name=region)
    paginator = ec2r.get_paginator("describe_spot_price_history")
    for page in paginator.paginate(
            Filters=[{
                "Name": "product-description",
                "Values": [pargs.product]
            }],
            InstanceTypes=pargs.instance_type,
            StartTime=pargs.start,
            EndTime=pargs.end):
        region_prices += page["SpotPriceHistory"]
        sys.stderr.write("%s %d\n" % (region, len(region_prices)))
    for price_point in region_prices:
        price_point["Region"] = region
        price_point["SpotPrice"] = float(price_point["SpotPrice"])
        # Assert that this is not a naive datetime, and that it is UTC. Naive datetimes will have
        # a None utcoffset(), but the explicit check is nice.
        assert price_point["Timestamp"].tzinfo is not None
        assert price_point["Timestamp"].utcoffset().total_seconds() == 0.0
        price_point["Timestamp"] = calendar.timegm(
            price_point["Timestamp"].utctimetuple())
    price_list += region_prices


def regularize(price_points):
    """
    Given a list of price points, resample them so they are event spaced, interpolating as necessary
    """
    # return price_points
    result = []
    start = price_points[0]["Timestamp"]
    end = price_points[-1]["Timestamp"]
    point_cursor = 0

    min_step = min([
        b["Timestamp"] - a["Timestamp"]
        for a, b in zip(price_points[:-1], price_points[1:])
    ])

    base_point = dict()
    base_point.update(price_points[0])
    del base_point["Timestamp"]
    del base_point["SpotPrice"]

    for i in xrange(start, end + 1, 1):
        if point_cursor == len(price_points) - 1:
            break

        if i >= price_points[point_cursor + 1]["Timestamp"]:
            point_cursor += 1

        point = dict()
        point.update(base_point)
        point["Timestamp"] = i
        point["SpotPrice"] = price_points[point_cursor]["SpotPrice"]
        result.append(point)

    if len(result) == 0:
        result.append(price_points[0])

    return result


def tabulate(prices):
    result = []
    for region, azs in prices.iteritems():
        for zone, instance_types in azs.iteritems():
            for instance_type, price_points in instance_types.iteritems():
                sys.stderr.write("%s %d\n" % (zone, len(price_points)))
                if len(price_points) == 0:
                    continue
                for k in ["Timestamp", "SpotPrice"]:
                    result.append([region, zone, instance_type, k] +
                                  [repr(p[k]) for p in price_points])

    # return "\n".join(map(lambda v: ",".join(v), zip(*result)))
    return "\n".join(map(",".join, result))


def __main():
    instance_types = [
        str(it["instance_type"])
        for it in json.loads(
            urllib2.urlopen("http://www.ec2instances.info/instances.json")
            .read())
    ]

    ec2_products = [
        "Linux/UNIX", "SUSE Linux", "Windows", "Linux/UNIX (Amazon VPC)",
        "SUSE Linux (Amazon VPC)", "Windows (Amazon VPC)"
    ]

    ec2 = boto3.client("ec2")
    regions = [str(r["RegionName"]) for r in ec2.describe_regions()["Regions"]]

    parser = argparse.ArgumentParser(
        description="""Get Ec2 pricing data given instance types in
    all regions""")
    parser.add_argument(
        "--region",
        action="append",
        default=[],
        help="""A region in which to find the price of the given instance types. Repeat this option
        for multiple regions. Default is all regions. Valid values are: %s""" %
        regions)
    parser.add_argument(
        "--instance-type",
        action="append",
        required=True,
        default=[],
        type=nonempty_list,
        help="""Instance type for which to retrieve spot pricing. Repeat this option for more
        instance types. Valid values are: %s""" % str(instance_types))
    parser.add_argument(
        "--start",
        type=dateutil.parser.parse,
        default=datetime.now(pytz.UTC) + timedelta(-7),
        help="""Start date and time from which to begin fetching spot prices, given in ISO
        8601 format. Default is 7 in the past.""")
    parser.add_argument(
        "--end",
        type=dateutil.parser.parse,
        default=datetime.now(pytz.UTC),
        help="""End date and time to use when fetching spot prices, , given in ISO 8601
        format. Default is now.""")
    parser.add_argument(
        "--product",
        type=str,
        required=True,
        help="""The AWS EC2 product to fetch pricing for. Valid values are: %s"""
        % ec2_products)
    parser.add_argument(
        "--output-format",
        type=str,
        required=False,
        default="json",
        help="""Format of output. Either "json" or "csv".""")
    pargs = parser.parse_args()

    nonempty_list(pargs.instance_type)
    if not set(pargs.instance_type).issubset(instance_types):
        raise ValueError(
            "Instance types given are not a subset of the allowed values.")

    if pargs.region == []:
        pargs.region = regions

    if not set(pargs.region).issubset(regions):
        raise ValueError(
            "Regions given are not a subset of the allowed values.")

    if pargs.product not in ec2_products:
        raise ValueError("Given EC2 product is not one of the allowed values.")

    price_list = []
    threads = []
    for region in set(regions).intersection(set(pargs.region)):
        t = threading.Thread(
            target=lambda r=region: get_region_prices(r, pargs, price_list))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    prices = tiered_dict(price_list,
                         ["Region", "AvailabilityZone", "InstanceType"])
    # Sort the price points by timestamp
    for r in prices.keys():
        for az in prices[r].keys():
            for it in prices[r][az].keys():
                prices[r][az][it] = regularize(
                    sorted(prices[r][az][it], key=lambda i: i["Timestamp"]))

    if pargs.output_format == "json":
        print json.dumps(prices)
    elif pargs.output_format == "csv":
        print tabulate(prices)


if __name__ == "__main__":
    __main()
