TMP=/mnt/c/Windows/Temp
LOCAL_TMP=/mnt/c/Users/janaka/AppData/Local/Temp

AWS_REG="us-east-1 us-east-2 us-west-1 us-west-2 ca-central-1 eu-west-1 eu-west-2 eu-west-3 eu-central-1 eu-north-1 ap-northeast-1 ap-northeast-2 ap-southeast-1 ap-southeast-2 ap-south-1 sa-east-1"

alias cmd=/mnt/c/Windows/System32/cmd.exe
alias adb=/mnt/c/Programs/Android/sdk/platform-tools/adb.exe
alias xcalib=/mnt/c/Programs/xcalib/xcalib.exe
alias VBoxManage=VBoxManage.exe
alias mysql="mysql -h 127.0.0.1"
alias msg=/mnt/c/Windows/System32/msg.exe

alias pip='pip2.7 --disable-pip-version-check'

alias notify-send="msg /time:3 janaka"
alias ok='notify-send "done" && date +%T'
function d_s() {
	date -d @$@ +"%Y-%m-%d %H:%M:%S"
}
function d() {
	date -d @$(($1/1000)) +"%Y-%m-%d %H:%M:%S"
}
function loop_d() {
	loop_d_func d
}
function loop_d_s() {
	loop_d_func d_s
}
function loop_d_func() {
	while true; do
		echo -n $'\n'"TS: "
		read TS
		$1 $TS
	done
}

alias myip='curl ipecho.net/plain'
function call() {
	readLn "Method" METHOD GET
	curl -X$METHOD "$@"
}

alias dlwg='wget -S --no-check-certificate --content-on-error --header="Accept-Encoding: gzip"'
alias dl='dlwg -O -'
alias dlsize='dl --method=HEAD'
alias dlu='dl --http-user'
alias dlq='dl -q'
alias dlb='dl --header="User-Agent: Firefox" --header="X-Requested-With: XMLHttpRequest"'
alias dlbsize='dlb -S --method=HEAD'

function bb_repos() {
	apicall "https://bitbucket.org/api/2.0/repositories/${1:-$BB_ORG}?pagelen=100&page=${2:-1}"
}
function bb_pr_approve() {
	bb_pr_op $1 $2 approve
}
function bb_pr_merge() {
	bb_pr_op $1 $2 merge
}
function bb_pr_check() {
	apicall https://bitbucket.org/api/2.0/repositories/$BB_ORG/$1/pullrequests
}

function bb_pr_open() {
	confirm "opening PR '$2' on $3 of '$1'"
	apicall https://bitbucket.org/api/2.0/repositories/$BB_ORG/$1/pullrequests --method POST --header "Content-Type: application/json" --body-data "{\"title\":\"$2\",
\"source\":{\"branch\":{\"name\":\"$3\"},\"repository\":{\"full_name\":\"janakaud/$1\"}},
\"destination\":{\"branch\":{\"name\":\"$3\"}},
\"close_source_branch\":false,
\"reviewers\":[{\"type\":\"user\",\"username\":\"$BB_USER_1\"}]}"
}

function bb_pr_decline() {
	bb_pr_op $1 $2 decline --header "Content-Type: application/json" --body-data "{\"reason\":\"$3\"}"
}

function bb_pr_op() {
	confirm "$3 $1 PR $2"
	apicall --method POST https://bitbucket.org/api/2.0/repositories/$BB_ORG/$1/pullrequests/$2/$3 "${@:4:$#}"
}

function bb_pr_patch() {
	bb_patch_op $1 pullrequests/$2/patch
}
function bb_commit_patch() {
	bb_patch_op $1 patch/$2
}
function bb_patch_op() {
	apicall https://bitbucket.org/api/2.0/repositories/$BB_ORG/$1/$2
}

function bb_new_repo() {
	apicall https://bitbucket.org/api/2.0/repositories/janakaud/$1 --header "Content-Type: application/json" --post-data '{"is_private":true}'
}
function bb_fork_repo() {
	apicall https://bitbucket.org/api/2.0/repositories/$BB_ORG/$1/forks --method POST
}
function bb_del_repo() {
	apicall_nogz https://bitbucket.org/api/2.0/repositories/janakaud/$1 --method DELETE
}

function gh_del_repo() {
	confirm "deleting GitHub repo $1"
	gh_api --method DELETE https://api.github.com/repos/janakaud/$1
}
function gh_new_repo() {
	confirm "creating GitHub repo $1"
	gh_api https://api.github.com/user/repos --post-data "{\"name\":\"$1\"}"
}
function gh_fork_repo() {
	confirm "forking GitHub repo $1 (:owner/:repo)"
	gh_api --method POST https://api.github.com/repos/$1/forks
}
function gh_repos() {
	gh_api https://api.github.com/user/repos
}
function gh_invites() {
	gh_api https://api.github.com/user/repository_invitations
}
function gh_invite_accept() {
	gh_api --method PATCH https://api.github.com/user/repository_invitations/$1
}

gh_token=$(cat ~/.config/cligh/cligh.conf | grep token | cut -d ' ' -f 2)
function gh_api() {
	dl --header "Authorization: Bearer $gh_token" "$@" | gunzip
}

function apicall() {
	apicall_nogz "$@" | gunzip
}
function apicall_nogz() {
	if [ "x$PASSWORD" == "x" ]; then
		dlu janakaud --ask-password --auth-no-challenge -q "$@"
	else
		dlu janakaud --http-password "$PASSWORD" --auth-no-challenge -q "$@"
	fi
}
function confirm() {
	echo -n "Press Ctrl-C to abort $1"
	read
}

function ghdl() {
	dlwg $(echo $1 | sed -e 's/github.com/codeload.github.com')/zip/master
}
function loop_url_rw() {
	while true; do
		echo -n $'\n'"URL: "
		read url
		$1 "$url"
	done
}

function server() {
	cd ~/html; serve >/dev/null 2>&1 & cd -
}

function short() {
	dl --header 'Content-Type: application/json' --post-data "{\"longUrl\":\"$1\"}" https://www.googleapis.com/urlshortener/v1/url?key=$GAPI_KEY | gunzip
}

function jetbrains_repo() {
	curl -vH 'Range: bytes=1305000-1340000' https://www.jetbrains.com/intellij-repository/snapshots/
}

function ymd_ms() {
	date -Iseconds -u -d @$(($1/1000))
}

alias showIssue='pyu --debug show issue'
function fixIssue() {
	COMMIT="$2"
	if [ -z $COMMIT ]; then
		echo -n "Commit: "
		read COMMIT
	fi
	resolveIssue $1 "Fixed in [$COMMIT](https://bitbucket.org/$BB_ORG/new-idea/commits/$COMMIT)" FIXED $3
}
function fixedIn() {
	readLn "Project" PROJECT "$1"
	readLn "Fix Version" FIXVER "$2"
	pyu list issues --project $PROJECT --filter "version: $FIXVER"
}

function resolveIssue() {
	readLn "Issue" ISSUE "$1"
	readLn "Comment" COMMENT "$2"
	readLn "State" STATE "$3"
	readLn "Fix Version" FIX_VERSION "$4"
	pyuConfirm update issue --comment "$COMMENT" --command "state $STATE add fixed in $FIX_VERSION" $ISSUE
}

function ytAfter() {
	_pyuAfter $1 "$2" "" ${@:3:$#}
}
function issuesAfter() {
	set -x
	_pyuAfter $1 "$2" "state: -Fixed -Closed -{Cannot Reproduce} -Duplicate -Incomplete" ${@:3:$#}
	set +x
}
function _pyuAfter() {
	readLn "Project" PROJECT "$1"
	readLn "Since epoch" LASTDAY "${2:-$(date +%s)000}"
	pyu ${@:4:$#} --debug list issues --project $PROJECT --filter "$3 created: $(date +%Y-%m-%dT%H:%M:%S -d @$(($LASTDAY/1000+1))) .. {Today}"
}
alias pyuAfter='pyu list issues --filter "created: $(date +%Y-%m-%dT%H:%M:%S -d @$(($LASTDAY/1000+1))) .. {Today}"'
alias inProgress='pyu update issue --command "state IN PROGRESS assigned to me"'

function readLn() {
	echo -n "$1 ($3): "
	read $2
	USER_VAL=$(eval "echo \$$2")
	if [ -z "$USER_VAL" ]; then
		eval "$2=\"$3\""
	fi
}
function pyuConfirm() {
	echo
	echo "${@:1:5}" "$6" ${@:7:$#}
	echo "Press Ctrl-C to abort"
	read
	pyu "$@"
}

function newIssue() {
	readLn "Project" PROJECT "$1"
	readLn "Summary" SUMMARY ""
	readLn "Description" DESCRIPTION ""
	readLn "Type" TYPE "Enhancement"
	readLn "Assignee" ASSIGNEE "me"
	readLn "Priority" PRIORITY "Major"
	readLn "Subsystem" SUBSYS "Sigma Console"
	pyuConfirm new issue $PROJECT "$SUMMARY" --command "type $TYPE priority $PRIORITY for $ASSIGNEE in $SUBSYS" --description "$DESCRIPTION"
}

alias data='watch -n 1 "ifconfig | grep -A7 enp[^1] | grep bytes"'
alias datawl='watch -n 1 "ifconfig wlp2s0 | grep bytes"'
alias top='top -o %MEM -d 1'
alias serveat='python -m SimpleHTTPServer '
alias serve='serveat 80'
alias trim='truncate --size=0'
function trail() { truncate --size=$((`du -b $1 | awk '{print $1}'` - 1)) $1; }
alias rmtmp='ORIG_DIR=$PWD; for tmp in $TMP $LOCAL_TMP /tmp; do cd $tmp && ( ls | grep -vE "^(\+~JF|prompthooks.py|jxbrowser|ultraesb-x|sys$|ram$|overflow$|home$)" | xargs rm -rf ); cd $ORIG_DIR; done'
alias srchhere='grep --exclude-dir=".*" -IF'
alias srchc='srchhere -R'
alias srch='srchc -i'
alias srchwork='srch --exclude-dir="node_modules*" --exclude-dir="target"'
alias host='sudo vi /etc/hosts'

alias dumpon='sudo tcpdump -A -vv -s 0'
alias dump='dumpon -i enp0s20f0u4'
alias dumpwl='dumpon -i wlp2s0'
alias dumpall='dumpon -i any'

function cdd() { cd `dirname $@`; }
alias strace='strace -e trace=file -f'

function offline() { sed -i -r -e "s/(url\(|[\"\'])((https?|):?|)\\\\?\/\\\\?\//\1file:\/\//g" -e "s/([\"\'])https?:[\"\']/\1file:\/\/\1/g" -e "s/src=([\'\"])/src=\1file:\/\//g" -e "s/<\/head>/<style type=\"text\/css\">pre\{white-space:pre-line;\}<\/style>&/g" "$1"; }
#function offline() { sed -i -r -e "s/(url\(|[\"\'])((https?|):?|)\\\\?\/\\\\?\//\1http:\/\/localhost\//g" -e "s/[\"\']https?:[\"\']/'http:\/\/localhost\/'/g" -e "s/src=[\'\"]\//src='http:\/\//g" -e "s/<\/head>/<style type=\"text\/css\">pre\{white-space:pre-line;\}<\/style>&/g" "$1"; }
function html() {
	echo "<html><body><pre style='font-size:19px'>"
	sed -e "s/→/\&rarr;/g" -e "s/[‐—]/-/g" -e "s/</\&lt;/g" -e "s/>/\&gt;/g"
	echo "</pre></body></html>"
}
function man2html() { man $1 | html; }
function cat2html() { cat $1 | html > $TMP/`basename $1`.html; }
function c2push() {
	finalpath=$TMP/`basename $1`.html
	cat2html $1
	push $finalpath && rm $finalpath
}

alias atob='base64 -d -'
alias btoa='base64 -w0'

alias temp='cat /sys/class/thermal/thermal_zone*/temp'
alias r='clear'

alias unzip='unzip -qq'

alias logsearch='find -name \*.log.gz -print0 | xargs -0 zgrep'

alias gaerun='python /opt/google/appengine/dev_appserver.py --log_level=debug .'
alias gaepush='rm -f *.pyc && python /opt/google-cloud-sdk/platform/google_appengine/appcfg.py --skip_sdk_update_check --oauth2'

alias vmls='VBoxManage list'
alias vmr='vmls runningvms'
alias vma='vmls vms'
alias vm='VBoxManage startvm --type=headless'

function jdk() { sudo ln -sfn /opt/jdk1.$1* /opt/jdk; }
alias toolbox='~/ultraesb/bin/toolbox.sh &'
alias mot='mvn -nsu -o'
alias m='mvn -DskipTests -DskipLoggingValidation'
alias mo='mot -DskipTests -DskipLoggingValidation'
alias mi='mo install'
alias mc='mo clean'
alias mp='mo package'
alias mt='mot test'
alias mpt='mot package'
alias mci='mo clean install'
alias mcio='m clean install'
alias mcit='mot clean install'
alias mcp='mo clean package'
alias mcpo='m clean package'
alias mcpt='mot clean package'
alias cleanall='for i in `find -maxdepth 3 -name "pom.xml"`; do cd `dirname $i`; mvn clean -o; cd $OLDPWD; done'
alias mtree='mo dependency:tree'
function mif() {
	pompath=$(unzip -l $1 | grep pom.xml | awk '{print $4}')
	unzip $1 $pompath -d /tmp/pom.xml
	mvn install:install-file -Dfile=$1 -DpomFile=/tmp/pom.xml/$pompath
}

alias revert='hg revert --no-backup'
alias hgpatch='hg patch --no-commit'
alias stu='hg st | grep -v -E "(^\? build|\.(iml|class)$)"'
function up() {
	if [ -d ".git" ]; then
		git pull $@
	else
		hg pull && hg up
	fi
}
function checkall() {
	vcsall st
}
function upall() {
	vcsall up
}
function vcsall() {
	for i in `find -mindepth 1 -maxdepth 1 -type d`; do
		cd $i
		$1
		cd -
	done
}
alias shelved='hg shelve -l'
function st() {
	if [ -d ".git" ]; then
		git status $@
	else
		hg st -madr $@
	fi
}

function swap() {
	if [ `dconf read /org/gnome/terminal/legacy/profiles:/:03fb11f5-ca71-4d42-a659-5c8a0f9d79fa/background-color` = "'rgb(255,255,255)'" ]; then
		dconf write /org/gnome/terminal/legacy/profiles:/:03fb11f5-ca71-4d42-a659-5c8a0f9d79fa/background-color "'rgb(0,0,0)'"
		dconf write /org/gnome/terminal/legacy/profiles:/:03fb11f5-ca71-4d42-a659-5c8a0f9d79fa/foreground-color "'rgb(0,255,0)'"
		gsettings set org.gnome.desktop.background picture-uri file:///usr/share/backgrounds/warty-final-ubuntu.png
		gsettings set org.gnome.desktop.interface gtk-theme 'Ambiance'
		mv ~/.config/terminator/config ~/.config/terminator/config_inv
		mv ~/.config/terminator/config_normal ~/.config/terminator/config
	else
		dconf write /org/gnome/terminal/legacy/profiles:/:03fb11f5-ca71-4d42-a659-5c8a0f9d79fa/background-color "'rgb(255,255,255)'"
		dconf write /org/gnome/terminal/legacy/profiles:/:03fb11f5-ca71-4d42-a659-5c8a0f9d79fa/foreground-color "'rgb(255,0,255)'"
		gsettings set org.gnome.desktop.background picture-uri file:///usr/share/backgrounds/Xerus_Wallpaper_Grey_4096x2304.png
		gsettings set org.gnome.desktop.interface gtk-theme 'Radiance'
		mv ~/.config/terminator/config ~/.config/terminator/config_normal
		mv ~/.config/terminator/config_inv ~/.config/terminator/config
	fi;
}
alias zkreen='xcalib -i -a'

anonssh='-oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no'
alias assh='ssh $anonssh '
alias asshp='ssh $anonssh -o GSSAPIAuthentication=no -o PubKeyAuthentication=no '
alias ascp='scp $anonssh '
alias asftp='sftp $anonssh '
alias sshcfg='chmod +w ~/.ssh/config && vi ~/.ssh/config && chmod 400 ~/.ssh/config'

alias awsj='aws --profile janaka'

function cf() { ${AWS:-aws} cloudformation $@; }
function cfls() { cf describe-stacks --query 'Stacks[*].StackName' --output text $@; }
function cfgs() { cf describe-stacks --stack-name $1 ${@:2:$#}; }
function cfcs() { cf create-stack --stack-name $1 --template-body fileb://$2 --capabilities CAPABILITY_IAM ${@:3:$#}; }
function cfus() { cf update-stack --stack-name $1 --template-body fileb://$2 --capabilities CAPABILITY_IAM ${@:3:$#}; }
function cfgt() { cf get-template --stack-name $1 ${@:2:$#}; }
function cfds() { cf delete-stack --stack-name $1 ${@:2:$#}; }
function cfse() { cf describe-stack-events --stack-name $1 --max-items ${2:-10} ${@:3:$#}; }
function invoke() {
	${AWS:-aws} lambda invoke --function-name $1 --payload "$2" --log-type Tail /tmp/$1.out --query LogResult --output text ${@:3:$#} | base64 -d
	ok
}

EC2_LS='ec2 describe-instances --query Reservations[*].Instances[*].[LaunchTime,KeyName,InstanceId,InstanceType,SecurityGroups[0].GroupId,PublicIpAddress,State.Name,Tags]'
EC2_IMG="ec2 describe-images --owners self --query Images"
EC2_SNAP="ec2 describe-snapshots --owner-ids self --query Snapshots"

alias imgs="aws $EC2_IMG"
alias snaps="aws $EC2_SNAP"
alias img='imgs --image-ids $@'
alias snap='snaps --snapshot-ids $@'

alias ec2ls='aws $EC2_LS'
alias ec2live='ec2ls --filter Name=instance-state-name,Values=running'
alias ec2up='aws ec2 start-instances --instance-ids'
alias ec2down='aws ec2 stop-instances --instance-ids'
alias ec2wait='aws ec2 wait instance-running --instance-ids'
function ec2run() {
	aws ec2 run-instances --image-id $1 --associate-public-ip-address \
--instance-type ${4:-t3a.micro} --security-group-ids ${5:-$DEFAULT_SECURITY_GROUP} --key-name $2 \
--tag-specifications ResourceType=instance,Tags='[{Key=Name,Value='$3'}]' ResourceType=volume,Tags='[{Key=Name,Value='$3'}]' ${@:6:$#}
}
function ec2tag() {
	aws ec2 create-tags --tags "Key=Name,Value=$1" --resources ${@:2:$#}
}
function ec2img() {
	aws ec2 create-image --instance-id $1 --name $2 ${@:3:$#}
}
function ec2rmi() {
	aws ec2 deregister-image --image-id $1 ${@:3:$#}
	aws ec2 delete-snapshot --snapshot-id $2 ${@:3:$#}
}
function ec2share() {
	ec2_img_share $1 $2 Add add $3
}
function ec2unshare() {
	ec2_img_share $1 $2 Remove remove $3
}
function ec2_img_share() {
	aws ec2 modify-image-attribute --image-id $1 --launch-permission $3'=[{UserId='${5:-$AWS_ACC}'}]'
	aws ec2 modify-snapshot-attribute --snapshot-id $2  --attribute createVolumePermission --operation-type $4 --user-ids ${5:-$AWS_ACC}
}

function ec2_ip() {
	sg_update authorize $@
}
function ec2_block() {
	sg_update revoke $@
}
function sg_update() {
	aws ec2 $1-security-group-ingress --group-id ${2:-$DEFAULT_SECURITY_GROUP} --ip-permissions \
"ToPort=${3:-22},FromPort=${3:-22},IpProtocol=tcp,IpRanges=[{CidrIp=${4:-$(curl ipecho.net/plain | cut -d . -f -2).0.0/16}}]" ${@:5:$#}
}

function awsall() {
	for region in $AWS_REG; do
		echo
		echo $region
		aws --region $region $@
	done
}

function checkbill() {
	for prof in $@; do
		echo
		echo "===="
		echo $prof
		for cmd in \
"kinesis list-streams --query StreamNames" \
"dynamodb list-tables --query TableNames" \
"rds describe-db-instances --query DBInstances[*].DBInstanceIdentifier" \
"rds describe-db-snapshots --query DBSnapshots" \
"rds describe-db-clusters --query DBClusters" \
"rds describe-db-cluster-snapshots --query DBClusterSnapshots" \
"elasticache describe-cache-clusters --query CacheClusters" \
"elasticache describe-snapshots --query Snapshots" \
"$EC2_LS" "$EC2_IMG" "$EC2_SNAP" \
		; do
			echo
			echo $cmd
			awsall --profile $prof $(echo $cmd)
		done
		echo
		echo "ML"
		for region in us-east-1 eu-west-1; do
			echo
			echo $region
			aws --region $region machinelearning describe-ml-models --query Results
		done
	done
}

alias now='date +%s000'
alias eeye='date -d @$((($(date +%s)-86400))) +%F'

function daybill() {
	yesterday=$(date -d @$((($(date +%s)-86400))) +%F)
	aws ce get-cost-and-usage --time-period Start=$yesterday,End=$(date +%F) --granularity=DAILY --metrics BlendedCost --group-by Type=DIMENSION,Key=SERVICE --profile $1
#OPERATION --output table --query 'ResultsByTime[*].[Groups[*].[Keys[0],Metrics.BlendedCost.Amount]]'
}

function dailybill() {
	ce_bill $1 DAILY
}
function monthbill() {
	ce_bill $1 MONTHLY
}
function ce_bill() {
	if [ $(date +%_d) -le 2 ]; then
		mon=$(($(date +%_m)-1))
		if [ $mon -le 9 ]; then mon=0$mon; fi
	else
		mon=$(date +%m)
	fi
	aws --profile $1 ce get-cost-and-usage --time-period Start=${START:-$(date +%Y)-$mon-01},End=${END:-$(date +%Y-%m-%d)} \
--granularity=$2 --metrics BlendedCost --group-by Type=DIMENSION,Key=${DIMENSION:-OPERATION}
}

alias s3loc='aws s3api get-bucket-location --bucket'
function s3ls() {
	aws s3 ls --recursive s3://$1 ${@:2:$#}
}
function s3rb() {
	aws s3 rb --force s3://$1 ${@:2:$#}
}
function s3rm() {
	aws s3 rm --recursive s3://$1 ${@:2:$#}
}
function s3cp() {
	aws s3 cp s3://$1 ${2:-/tmp/} ${@:3:$#}
}
function s3sizes() {
	REGION=${AWS_DEFAULT_REGION:-${AWS_REGION:-"us-east-1"}}
	defolts=()
	killall awsr; rm /tmp/awsr_*
	for bucket in `awsr s3api list-buckets --query 'Buckets[*].Name' --output text $@`; do
#	for bucket in a b c d e-us-west-1 f g h i-ap-southeast-1 j k foo-bar-123 x-c-d-3; do
		region=$(echo $bucket | grep -oP "(us|eu|ap|sa|cn)-\w+-\d\b")
		if [ "$region" = "$REGION" ] || [ -z $region ]; then
			defolts+=($bucket)
			continue
		fi
		_s3_size $bucket aws --region $region $@
	done
	for bucket in ${defolts[@]}; do
		_s3_size $bucket awsr $@
	done
}
function _s3_size() {
	size=$(AWS=${2:-aws} s3size $1 --output text --query 'Datapoints[0].Average' ${@:3:$#})
#echo $size
#echo '
	if [ $size = "None" ]; then size=0; fi
	printf "%8.3f  %s\n" $(echo $size/1048576 | bc -l) $1
#'>/dev/null
}

function s3size() {
	s3metric BucketSizeBytes StandardStorage $@
}
function s3count() {
	s3metric NumberOfObjects AllStorageTypes $@
}
function s3metric() {
	${AWS:-aws} cloudwatch get-metric-statistics --namespace AWS/S3 --start-time ${START:-$(eeye)}T00:00:00 --end-time ${END:-$(date +%F)}T00:00:00 --period 86400 --metric-name $1 --dimensions Name=StorageType,Value=$2 Name=BucketName,Value=$3 --statistics Average ${@:4:$#}
}

function s3expire() {
	readLn "Days" days 1
	aws s3api put-bucket-lifecycle-configuration --lifecycle-configuration '{"Rules":[{"Status":"Enabled",
"Expiration":{"Days":'$days'},
"NoncurrentVersionExpiration":{"NoncurrentDays":'$days'},
"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":'$days'},
"Prefix":""}]}' --bucket $@
}
function s3expire-versioned() {
	aws s3api put-bucket-lifecycle-configuration --lifecycle-configuration '{"Rules":[{"Status":"Enabled","Expiration":{"ExpiredObjectDeleteMarker":true},"NoncurrentVersionExpiration":{"NoncurrentDays":1},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1},"Prefix":""}]}' --bucket $@
}
function s3unexpire() {
	aws s3api delete-bucket-lifecycle --bucket $@
echo >/dev/null \
	aws s3api put-bucket-lifecycle-configuration --lifecycle-configuration '{"Rules":[{"Status":"Disabled","Prefix":"","Expiration":{"Days":3650}}]}' --bucket $@
}
function s3life() {
	aws s3api get-bucket-lifecycle-configuration --bucket $@
}

function logs() {
	startTime=${START:-$(($(now)-600000))}
	limit=${LIMIT:-20}
	echo "$limit, >$startTime"$'\n'
	if [ -z $LOG_GROUP ]; then	# fallback to /aws/lambda; filter streams for today
		streamPrefix="\"logStreamNamePrefix\":\"${LOG_STREAM_PREFIX:-$(date -u -d @$(($startTime/1000)) +%Y/%m/%d)}\","
	else
		streamPrefix=""
	fi
	if [ -n "$2" ]; then
		filter="\"filterPattern\":\"$2\","
	else
		filter=""
	fi
	# --limit doesn't work
	${AWS:-aws} logs filter-log-events --no-paginate --query 'events[*].[timestamp,message]' --output text --cli-input-json \
"{\"logGroupName\":\"${LOG_GROUP:-/aws/lambda/$1}\",$streamPrefix\"limit\":$limit,$filter\"startTime\":$startTime,\"endTime\":${END:-$(now)}}" ${@:3:$#}
}
function log_check() {
	if [ -n "$INTERVAL" ]; then
		interval=$INTERVAL
	elif [ -z $3 ]; then
		interval=60
	else
		interval=600
	fi
	readLn "Log group suffix: /aws/lambda/" logGroup $1
	readLn "Start time, UTC (interval=$interval)" startTime "${2:-$(d_s $(($(date +%s)-$interval)) -u)}"
	start=$(date -d "$startTime"+00:00 +%s%3N)
	if [ -z $start ]; then return 0; fi
	stop=$(($start+$interval$(echo 000)))
#	readLn "End time, UTC (default: $(date -d @$(($stop/1000)))" endTime
echo "End: $(date -d @$(($stop/1000)))"
set -x
	START=$start END=$stop logs "$logGroup" "${@:3:$#}"
set +x
}

function awscred() {
	readLn "AWS Access Key" accessKey
	readLn "AWS Access Secret" accessSecret
	export AWS_ACCESS_KEY_ID=$accessKey
	export AWS_SECRET_ACCESS_KEY=$accessSecret
	export AWS_DEFAULT_REGION=us-east-1
}
function clearAWS() {
	unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION;
}

function gh() { gcloud $@ --help; }

alias watch='watch -n 1 '
alias enve='vi ~/.bashrc_custom && source ~/.bashrc_custom'
alias enves='vi ~/.bashrc_secret && source ~/.bashrc_secret'
alias alie='vi ~/.bash_aliases && source ~/.bash_aliases'
alias alies='vi ~/.bash_aliases_secret && source ~/.bash_aliases_secret'

alias vacred='vi ~/.aws/credentials'
alias vhis='vi ~/.bash_history'

alias sys='kubectl --namespace=kube-system'
alias pod='kubectl get pods'
alias create='kubectl create'
alias log='kubectl logs'
alias get='kubectl get'
alias desc='kubectl describe'
alias svc='kubectl get svc'
alias rc='kubectl get rc'
alias rs='kubectl get rs'
alias dep='kubectl get deployment'
alias nodes='kubectl get nodes'
alias del='kubectl delete'
alias deldep='kubectl delete deployment'
alias editdep='kubectl edit deployment'
alias edit='kubectl edit'
alias tomcat='/opt/tomcat/bin/catalina.sh start'
alias kssh='kubectl exec -it'
alias klocal='kubectl config use-context ubuntu'
function findapp() { kubectl get $1 -lapp=$2 -oname | cut -b 6-; }
function kapp() { findapp pod $1; }
function esblog() { kubectl logs -f `kapp ultraesb`; }

alias ipssys='kubectl --namespace=ips-system'
alias ipspod='ipssys get pods'
alias ipssvc='ipssys get svc'
alias ipsdel='ipssys delete'
alias ipslog='ipssys logs'
function ipsssh() { ipssys exec -it $1 sh; }

alias i='kubectl --namespace=ips'
alias ipod='i get pods'
alias idel='i delete'
alias idep='i get deployments'
alias isvc='i get svc'
alias ilog='i logs'
function issh() { i exec -it $1 sh; }

alias sysget='sys get'
alias syspod='sys get pods'
alias syslog='sys logs'
alias sysdesc='sys describe'
alias syssvc='sys get svc'
alias sysrc='sys get rc'
alias sysdel='sys delete'
alias sysedit='sys edit'
function sysssh() { sys exec -it $1 sh; }
function delapp() { sysdel pod -l app=$1; }
function sysapp() { findapp syspod $1; }

#konly=(kube-apiserver kube-controller-manager kube-scheduler kube-proxy kubelet)
konly=(kubelet)
#donly=(etcd flannel docker)
donly=(docker)
kall=(${donly[@]} ${konly[@]})
function kmgt() { for i in ${@:1:$#-1}; do sudo service $i ${!#}; done }
alias kreboot='kmgt ${konly[@]} restart'
alias knreboot='for i in kubelet kube-proxy; do sudo service $i restart; done'
alias kup='kmgt ${kall[@]} start'
alias kstop='kmgt ${konly[@]} stop'
alias kdown='kmgt ${kall[@]} stop'
alias kstat='for i in ${kall[@]}; do service $i status | grep -B2 "Active:" | grep -v "Loaded:" | grep -E "failed|inactive|exited|$"; done'
alias eskill='for i in `ps -ef | grep Elastic | awk '\''{print $2}'\''`; do kill $i; done'
alias es='/opt/es/bin/elasticsearch'
alias mysqls='sudo service mysql restart'

#function tscw() { tsc -w | grep -vE "node_modules|'Map'|troubleshoot|only supported in ECMAScript 6"; }
#alias tsc='tsc | grep -vE "node_modules|Map|troubleshoot|only supported in ECMAScript 6"'
alias noderun='concurrently "tsc -w" lite-server'
#alias noderun='concurrently tscw lite-server'

alias dup='kmgt ${donly[@]} start'
alias ddwn='kmgt ${donly[@]} stop'
alias dimg='docker images'
alias dpush='docker push'
alias dclean='docker rmi -f `docker images -f "dangling=true" -q`; docker rm -f `docker ps -f "status=exited" -f "status=created" -q`'
alias drun='docker run --rm -it --entrypoint=sh'
alias dhis='docker history --no-trunc'
alias drmi='docker rmi -f'
alias dps='docker ps -a --no-trunc'
function dbu() { docker build -t $1 .; }

function push() {
	path="$2"
	if [ -z $path ]; then
		path="/sdcard/"
	fi
	cmd /C adb push "$1" $path && ok
}
function htmlpush() {
	files=$@
	if [ -z $files ]; then
		files=$TMP/*htm*
	fi

	for i in $files; do
		offline $i
		push $i /sdcard/read/ && rm $i
	done
}
alias hp='htmlpush'
function whatsapp() { watch -n 10 "adb.exe shell 'ps | grep whats' | notify-send"; }

alias movie='du -ks /Users/janaka/Videos/* | sort -n'
function movie0() { moviepush 0 "$1"; }
function movie1() { moviepush 1 "$1"; }
function moviepush() { push "$2" "/storage/sdcard$1/Movies/`basename "$2"`"; }

function pull() {
	path=$2
	if [ -z $path ]; then
		path="$TMP/"
	fi
	cmd /C adb pull /sdcard/$1 $path
}
alias ms='adb shell'
alias mdf='ms busybox df'

function dim() {
	level=$1
	if [ -z $level ]; then
		level="20"
	fi
	echo $level | sudo tee /sys/class/backlight/intel_backlight/brightness
}

alias fd='cat /sys/proc/fs/file-nr'
alias runnin='service --status-all | grep -vF "[ - ]"'
alias p='ps -ef|grep '
alias killit='killsig -9'
alias dumpit='killsig -3'
alias termit='killsig -15'
function pid() {
	ps -ef | grep $1 | grep -v grep | awk '{print $2}'
}
function killsig() {
	for i in `pid $2`; do
		kill $1 $i
	done
}

function bintail() { xxd $1 | tail -n5; }

function nunzip() { echo "Archive:$1"; unzip -l $1; }
function findinjar() {
	ext=$2
	if [ -z $ext ]; then
		ext="jar"
	fi
	for i in `find . -name "*$ext"`; do
		nunzip "$i" | grep -E "Archive:|$1" | grep -B1 -E "$1"
	done
}
function findinname() {
	find -iname "*$1*" ${@:2:$#}
}
function xprjar() {
	unzip -l $1 | awk '{print $4}' | grep jar | cut -b 5-
}

alias gputop='sudo intel_gpu_top'
alias gpucheck='sudo intel_gpu_frequency -g'
function gpuwatch() {
	while [ 1 ]; do
		freqs=$(sudo intel_gpu_frequency -g)
		max=$(echo "$freqs"|grep max|awk '{print $2}')
		cur=$(echo "$freqs"|grep cur|awk '{print $2}')
		if [[ $cur -lt $max ]]; then
			notify-send "throttled $cur"
		fi
		sleep 3
	done
}
function gputhrottle() {
	while [ 1 ]; do
		echo "Start $(date)"
		boinccmd --passwd "" --set_gpu_mode always -1
		sleep 61
		echo "Pause $(date)"
		boinccmd --passwd "" --set_gpu_mode never -1
		sleep 100
	done
}

alias srcha='grep -iIr --include="*.adoc"'
function loop_srcha() {
	while true; do
		echo -n $'\n'"Phrase: "
		read phrase
		srcha "$phrase"
	done
}

function asciibuild() {
	asciibinder build -p $1/$2:$3
}
alias idebug='/opt/idea/jre/bin/java -Xbootclasspath/a:/opt/idea/lib/boot.jar -classpath /opt/idea/lib/bootstrap.jar:/opt/idea/lib/extensions.jar:/opt/idea/lib/util.jar:/opt/idea/lib/jdom.jar:/opt/idea/lib/log4j.jar:/opt/idea/lib/trove4j.jar:/opt/idea/lib/jna.jar:/opt/idea/jre/lib/tools.jar -Xdebug -Xnoagent -Xrunjdwp:transport=dt_socket,server=y,address=8000 -Xms128m -Xmx750m -XX:ReservedCodeCacheSize=240m -XX:+UseConcMarkSweepGC -XX:SoftRefLRUPolicyMSPerMB=50 -ea -Dsun.io.useCanonCaches=false -Djava.net.preferIPv4Stack=true -XX:+HeapDumpOnOutOfMemoryError -XX:-OmitStackTraceInFastThrow -Dawt.useSystemAAFontSettings=lcd -Dsun.java2d.renderer=sun.java2d.marlin.MarlinRenderingEngine -XX:ErrorFile=/home/janaka/java_error_in_IDEA_.log -XX:HeapDumpPath=/home/janaka/java_error_in_IDEA.hprof -Didea.paths.selector=IntelliJIdea2017.1 -Djb.vmOptionsFile=/opt/idea/bin/idea64.vmoptions -Didea.jre.check=true com.intellij.idea.Main'
alias jre='drun -v `pwd`:/tmp openjdk:8-jre-alpine'

function zabup() { zabop start; }
function zabdown() { zabop stop; }
function zabop() {
	for svc in zabbix-agent zabbix-server apache2; do
		service $svc $1
	done
}


if [ -f ~/.bash_aliases_secret ]; then
	. ~/.bash_aliases_secret
fi
