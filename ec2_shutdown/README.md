When running an EC2 instance and using it for interactive workflows, it can be a pain to remember to shut it down. This is a little pair of bash script and some cron entries that shut down the instance when it has been up for at least `N` minutes, no user has logged in in the past `N` minutes, and 1-minute load averges over the last `N` minutes have never exceeded some value.

This is not aware of EC2 billing periods and makes no attempt to stay up for a billing-hour.

## Cron entries
```bash
* * * * * uptime >> /var/log/`curl -s http://169.254.169.254/latest/meta-data/public-ipv4`-uptime.log
* * * * * tail -n60 /var/log/`curl -s http://169.254.169.254/latest/meta-data/public-ipv4`-uptime.log | bash /root/uptime_check.sh 60
```

## `/root/uptime_check.sh`
```bash
#!/bin/bash
lines=$(cat - | sed 's/^.* \([0-9]*\) user.*load average: \(.*\), \(.*\), \(.*\)$/\1 \2 \3 \4/')
nlines=$(echo "$lines" | wc -l)
if [ $nlines -lt $1 ]
then
    echo "Only up for $nlines minutes"
    exit
fi

load_avg=$(echo "$lines" | cut -d ' ' -f2 | sort -n | tail -n1 | cut -d'.' -f1)
users=$(echo "$lines" | cut -d ' ' -f1 | sort -n | tail -n1)

if [ $load_avg -gt 2 ]
then
    echo "Peak of $load_avg CPU load over invterval"
    exit
fi

if [ $users -gt 0 ]
then
    echo "Peak of $users user over interval"
    exit
fi

shutdown -h now
```
