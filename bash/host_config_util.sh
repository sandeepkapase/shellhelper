#!/bin/bash
# Host Management/Configuration Tool
# TODO: 1) Configuration file based operations
#       2) Parameter based (cmdline) operations
#       3) Logger functionality for operations/activities
#       4) Partitioning support (if required)
#       4) Strict error handling.

set -o nounset # unset variables as an error
set -o monitor # enable job control

#trap '$ECHO "child died $((pCheck=1))" > /dev/null' CHLD
#trap - CHLD

export ECHO=$(which echo)  # system's default $ECHO

[ -z "$BASH_VERSION" ] && { $ECHO "Bash version info not available.\
        Please check bash version" ; exit 1 ; }

source data_base64.sh

DRBDCONF_TEMPLATE_VAR=\
'global { usage-count no; }
common { syncer { rate 100M; } }
resource RESOURCE {
        protocol C;
        startup {
                wfc-timeout  15;
                degr-wfc-timeout 60;
        }
        handlers {
                split-brain "/usr/lib/drbd/notify-split-brain.sh root";
        }
        net {
                cram-hmac-alg sha1;
                shared-secret "secret";
                after-sb-0pri discard-zero-changes;
                after-sb-1pri discard-secondary;
                after-sb-2pri disconnect;
        }
        on ubuntu.node1.com {
                device /dev/drbd0;
                disk /dev/DRBD_BAKDEV1;
                address HOST1_ADDRESS;
                meta-disk internal;
        }
        on ubuntu.node2.com {
                device /dev/drbd0;
                disk /dev/DRBD_BAKDEV2;
                address HOST2_ADDRESS;
                meta-disk internal;
        }
}'


# VAR=

readonly ERROR=1
export ERROR
readonly SUCCESS=0
export SUCCESS
readonly EXIT=2
export EXIT

declare -A valMap

valMap[confighome]="$HOME/.hostcfg"
valMap[libbin]="$HOME/.hostcfg/libbin"
valMap[lockfile]="$HOME/.hostcfg/lock"
valMap[tui]="$HOME/.hostcfg/libbin/tui"
valMap[tuisum]="09e93b2615b65090b499ce160ebae340"
valMap[tuilib]="$HOME/.hostcfg/libbin/libnewt.so.0.52"
valMap[tuilibsum]="c70f620b7212ff5b6686e812bea469d0"
valMap[sshpass]="$HOME/.hostcfg/libbin/sshpass"
valMap[sshpasssum]="ad46cc8e5c30a09e385b2fa4516b2223"
valMap[drbdutil]="$HOME/.hostcfg/libbin/drbd-utils_8.9.1+linbit-1+~cmd1~trusty1_amd64.deb"
valMap[drbdutilname]="drbd-utils"
valMap[drbdutilsum]="10c31ba4b14b0819379b9d391934ec04"
valMap[drbd8util]="$HOME/.hostcfg/libbin/drbd8-utils_2%3a8.9.1+linbit-1+~cmd1~trusty1_amd64.deb"
valMap[drbd8utilname]="drbd8-utils"
valMap[drbd8utilsum]="9259b38592a4e8ac9325244da1c4e056"
valMap[statusfile]="/dev/shm/pstatus"
valMap[drbdmodname]="drbd"
valMap[drbdconffile]="/etc/drbd.conf"
valMap[drbdmodversion]="8.4.5"
valMap[drbdadm]="/usr/sbin/drbdadm"
valMap[drbddefresource]="r0"
valMap[drbdservice]="drbd"
valMap[menu_title]="'Configuration tool for DRDB, HA, Samba, NFS ( Ubuntu 14.04 ) [WIP] '"

export valMap

function mapVal()
{
    [ ${valMap[$@]+_} ] && { $ECHO ${valMap[$@]} ; return $SUCCESS ; }
    which $@ 2> /dev/null || { $ECHO "BLACKHOLE" ; return $ERROR ; }
}

export CONFIG_HOME=$(mapVal confighome)
export LD_LIBRARY_PATH=$(mapVal libbin)
export DIRNAME=$(mapVal dirname)
export SSH=$(mapVal ssh)
export SCP=$(mapVal scp)
export SSHCOPYID=$(mapVal ssh-copy-id)
export SSHKEYGEN=$(mapVal ssh-keygen)
export SSH_EXEC_CMD=""
export FLOCK=$(mapVal flock)
export HEAD=$(mapVal head)
export TAIL=$(mapVal tail)
export DRBDADM=$(mapVal drbdadm)
export DRBD_DEF_RESOURCE=$(mapVal drbddefresource)
export SERVICE=$(mapVal service)
export DRBD_SERVICE=$(mapVal drbdservice)
export DPKG=$(mapVal dpkg)
export LSMOD=$(mapVal lsmod)
export MODINFO=$(mapVal modinfo)
export MODPROBE=$(mapVal modprobe)
export MD5SUM=$(mapVal md5sum)
export AWK=$(mapVal awk)
export SED=$(mapVal sed)
export BZIP2BIN=$(mapVal bzip2)
export base64=$(mapVal base64)
export OPENSSL=$(mapVal openssl)
export SU=$(mapVal su)
export NC=$(mapVal nc)
export CUT=$(mapVal cut)
export CAT=$(mapVal cat)
export MKDIR=$(mapVal mkdir)
export STAT=$(mapVal stat)
export DATE=$(mapVal date)
export GREP=$(mapVal grep)
export SLEEP=$(mapVal sleep)
export TPUT=$(mapVal tput)
export TUI_BIN=$(mapVal tui)
export TUI_BINSUM=$(mapVal tuisum)
export TUI_LIB=$(mapVal tuilib)
export TUI_LIBSUM=$(mapVal tuilibsum)
export SSHPASS_BIN=$(mapVal sshpass)
export SSHPASS_BINSUM=$(mapVal sshpasssum)
export MENU_TITLE=$(mapVal menu_title)
export MNU_HT=$(($($TPUT lines)/3))
export MNU_AD=$(($($TPUT cols)/2))
export MNU_LN_HT=$(($($TPUT lines)/3-7))
export PLIST=""
export STATUSFILE=$(mapVal statusfile)
export DRBDMOD_NAME=$(mapVal drbdmodname)
export DRBD_CONF_FILE=$(mapVal drbdconffile)
export DRBDMOD_VERSION=$(mapVal drbdmodversion)
export DRBDUTIL_PKG=$(mapVal drbdutil)
export DRBDUTIL_PKGNAME=$(mapVal drbdutilname)
export DRBDUTIL_PKGSUM=$(mapVal drbdutilsum)
export DRBD8UTIL_PKG=$(mapVal drbd8util)
export DRBD8UTIL_PKGNAME=$(mapVal drbd8utilname)
export DRBD8UTIL_PKGSUM=$(mapVal drbd8utilsum)
export PROGRESS=100
export PCHK_INTERVAL=5
export MENU_SUBTITLE=""
export MENU_INPUT_DEFVAL=""
export OPTIONS=""
export SSHUSER=""
export SSHHOST=""
export DEFUSER="root"
export HOST1_ADDRESS=""
export HOST2_ADDRESS=""
export HOST1_IP=""
export HOST2_IP=""
export DRBD_BAKDEV1=""
export DRBD_BAKDEV2=""
export SSHPASS=""
export LCK_EXEC=""
export LCK_FD="123"
export pCheck=1
export pids=""
export okPids=""
export errPids=""
export gcounter=0
export INTERACTIVE=1
export ASK_TO_REBOOT=1
readonly LOCKFILE=$(mapVal lockfile)
export LOCKFILE

function RunNoErr()
{
    $@ 2> /dev/null || return $ERROR
}

function tmpClean()
{
    $DRBDADM down $DRBD_DEF_RESOURCE
    $SERVICE $DRBD_SERVICE  stop
    $MODPROBE modprobe -r $DRBDMODNAME
    $RM -rf /var/lib/drbd
    $DPKG -r $DRBD8UTIL_PKGNAME
    $DPKG -P $DRBD8UTIL_PKGNAME
    $DPKG -r $DRBDUTIL_PKGNAME
    $DPG -P $DRBDUTIL_PKGNAME
    $RM -rf $DRBD_CONF_FILE ~/.hostcfg/
    $RM -rf ~/.ssh*
}

function lockConfig()
{
    RunNoErr $MKDIR -p `$DIRNAME $LOCKFILE`
    [ -d $($DIRNAME $LOCKFILE) ] || { $ECHO Failed to create $LOCKFILE | return $ERROR ; }
}

function errmsg()
{
    $CAT - 1>&2
}

function waitprogress()
{
  pName="$@"
  shift $#
  for i in $pName
  do
      $i &
      set -- "$@" "$!"
  done
  errPids=""
  okPids=""
  start=$($DATE +%s)
  local errors=0
  while :; do
    #$ECHO "Premaining:-[$*]"
    for pid in "$@"; do
      shift
      if kill -0 "$pid" 2>/dev/null; then
        #$ECHO "$Running [$pid] now"
        set -- "$@" "$pid"
      elif wait "$pid"; then
        #$ECHO "Completed [$pid]."
        okPids="$okPids $pid"
      else
        #$ECHO "Failed [$pid]."
        errPids="$errPids $pid"
        ((++errors))
      fi
    done
    (("$#" > 0)) || break
    $SLEEP 1
    [ $((`$DATE +%s`-start)) -gt 99 ] && { $ECHO 99 ; continue; }
    $ECHO $((`$DATE +%s`-start))
   done
   $ECHO 100
  ((errors == 0))
}

function isRoot()
{
    [ "$(id -u)" == "0" ] || return $ERROR
}

function MENU_INPUT_PASS()
{
    $TUI_BIN --title "$MENU_TITLE" --passwordbox "$MENU_SUBTITLE" $((MNU_HT/2)) $MNU_AD 3>&2 2>&1 1>&3-
    return $?
}

function MENU_INPUT()
{
    $TUI_BIN --title "$MENU_TITLE" --inputbox "$MENU_SUBTITLE" $((MNU_HT/2)) $MNU_AD "$MENU_INPUT_DEFVAL" 3>&2 2>&1 1>&3-
    return $?
}

function exitMSg()
{
    $CAT $STATUSFILE
}


function SSH_ACCESS()
{
    $SSH -o StrictHostKeyChecking=no -o PasswordAuthentication=no \
        $SSHUSER@$SSHHOST exit 2> /dev/null && $ECHO 0 > $STATUSFILE || \
        $ECHO 1 > $STATUSFILE
}


function SSH_EXEC()
{
    $SSH -o StrictHostKeyChecking=no -o PasswordAuthentication=no $1@$2 $SSH_EXEC_CMD
    return $?
}

function DRBD_PKG_INSTALL()
{
    $LSMOD | $GREP -i $DRBDMOD_NAME > /dev/null || $MODPROBE $DRBDMOD_NAME  2> /dev/null || \
        { $ECHO "Failed To Load DRBD module. Abort Setup..." > $STATUSFILE; return $ERROR ; }

    [ "$($MODINFO $DRBDMOD_NAME | $GREP -w version  | $AWK '{ print $2 }')" == "$DRBDMOD_VERSION" ] || \
        { $ECHO "Expected DRBD module version $DRBDMOD_VERSION not found. Abort Setup..." > $STATUSFILE ; \
            return $ERROR ; }

    $DPKG -s $DRBDUTIL_PKGNAME &> /dev/null || $DPKG -i $DRBDUTIL_PKG &> /dev/null || \
        { $ECHO "Package Installation Failed For $DRBDUTIL_PKG. Aborting Setup..." > $STATUSFILE; \
            return $ERROR ; }

    $SLEEP 3

    $DPKG -s $DRBD8UTIL_PKGNAME &> /dev/null || $DPKG -i $DRBD8UTIL_PKG &> /dev/null || \
        { $ECHO "Package Installation Failed For $DRBD8UTIL_PKG. Aborting Setup..." > $STATUSFILE ; \
            return $ERROR ; }

    SSH_EXEC_CMD="[ -d  $LD_LIBRARY_PATH ] || $MKDIR -p $LD_LIBRARY_PATH"; SSH_EXEC $DEFUSER $HOST2_IP || \
        { $ECHO "Remote Mkdir For $LD_LIBRARY_PATH Failed. Aborting Setup..." > $STATUSFILE; \
            return $ERROR ; }

    ($CAT $DRBDUTIL_PKG) | { SSH_EXEC_CMD="cat - > $DRBDUTIL_PKG" ; SSH_EXEC $DEFUSER $HOST2_IP; }

    ($CAT $DRBD8UTIL_PKG) | { SSH_EXEC_CMD="cat - > $DRBD8UTIL_PKG" ; SSH_EXEC $DEFUSER $HOST2_IP; }

    # TODO checksum verification here

    SSH_EXEC_CMD="$DPKG -i  $DRBDUTIL_PKG" ; SSH_EXEC $DEFUSER $HOST2_IP &> /dev/null || \
        { $ECHO "Remote Package Installation Failed For $DRBDUTIL_PKG. Aborting Setup..." > $STATUSFILE; \
            return $ERROR ; }

    $SLEEP 3

    SSH_EXEC_CMD="$DPKG -i  $DRBD8UTIL_PKG"; SSH_EXEC $DEFUSER $HOST2_IP &> /dev/null || \
        { $ECHO "Remote Package Installation Failed For $DRBD8UTIL_PKG. Aborting Setup..." > $STATUSFILE ; \
            return $ERROR ; }

    $ECHO "0" > $STATUSFILE && return $SUCCESS
}

function DRBD_SERVICE_RESTART()
{
   $SERVICE $DRBD_SERVICE restart &> /dev/null &
   pid=$!
   SSH_EXEC_CMD="$SERVICE $DRBD_SERVICE restart"
   SSH_EXEC $DEFUSER $HOST2_IP &> /dev/null || return $ERROR
   wait $pid &> /dev/null || return $ERROR
   return $SUCCESS
}

function DRBD_RESOURCE_CONFIGURE()
{
    # drbd config file
    DRBDCONFVAR=$(IFS="@@@@" ; $SED -e s/RESOURCE/$DRBD_DEF_RESOURCE/g \
        -e s/DRBD_BAKDEV1/$DRBD_BAKDEV1/g -e s/DRBD_BAKDEV2/$DRBD_BAKDEV2/g \
        -e s/HOST1_ADDRESS/$HOST1_ADDRESS/g -e s/HOST2_ADDRESS/$HOST2_ADDRESS/g <<< $DRBDCONF_TEMPLATE_VAR )

    (IFS="@@@@" ;  $ECHO $DRBDCONFVAR > $DRBD_CONF_FILE )

    (IFS="@@@@" ;  $ECHO $DRBDCONFVAR) | \
        { SSH_EXEC_CMD="cat - > $DRBD_CONF_FILE" ; SSH_EXEC $DEFUSER $HOST2_IP; }


   ($ECHO -e 'yes\nyes' | $DRBDADM create-md $DRBD_DEF_RESOURCE) &> /dev/null || \
       { $ECHO "create-md failed on current host" >  $STATUSFILE ; return $ERROR ; }


   SSH_EXEC_CMD="$ECHO -e 'yes\nyes' | $DRBDADM create-md $DRBD_DEF_RESOURCE"
   SSH_EXEC $DEFUSER $HOST2_IP &> /dev/null || { $ECHO "create-md failed on remote host" ; > \
       $STATUSFILE ; return $ERROR ; }


   DRBD_SERVICE_RESTART || { $ECHO "DRBD Service Restart Failed" > $STATUSFILE ; return $ERROR ; }

   $DRBDADM -- --overwrite-data-of-peer primary all $DRBD_DEF_RESOURCE

   $ECHO 0 > $STATUSFILE
   return $SUCCESS
}

function DO_CONFIGURE_DRBD()
{
    MENU_SUBTITLE="Please follow DRBD Configuration wizard to complete setup. You \
will be asked to input configuration paramenter for two DRBD nodes."
    MENU_MSG

    NWIF=$(/sbin/route -n | $GREP ^0.0.0.0 | $AWK 'NF>1{print $NF}' | $HEAD -n 1)
    IFIP=$(/sbin/ifconfig $NWIF | $GREP -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\
)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\
)\.(25[0-5]|2[0-4][0-9]|[01]?[0 -9][0-9]?)"|$HEAD -n 1)

    MENU_INPUT_DEFVAL=$IFIP:7788
    while true
    do
        MENU_SUBTITLE="Enter First Node(current node) Address [host:port]:"
        HOST1_ADDRESS=$(MENU_INPUT)

        [ $? -ne 0 ] || break
        MENU_SUBTITLE="Are you sure you want to stop configuration ?"
        MENU_YESNO
        [ $? -eq 0 ] && return $ERROR
    done

    OPTIONS=""
    for i in $($CAT /proc/partitions  | $GREP '[^[:blank:]]' | $GREP -v major | $AWK '{print $4}')
    do
        OPTIONS=$OPTIONS" "$i" "/dev/$i" "OFF
    done

    while true
    do
        MENU_SUBTITLE="Choose Device (First Node): "
        DRBD_BAKDEV1=$(MENU_OPTIONS)
        if test $? -ne 0
        then
            MENU_SUBTITLE="Are you sure you want to stop configuration ?"
            MENU_YESNO
            [ $? -eq 0 ] && return $ERROR
        else
            if [ -z "$DRBD_BAKDEV1" ]
            then
                MENU_SUBTITLE="Device not selected. Please select DRBD device(First Node)."
                MENU_MSG
                continue
            fi
            break
        fi
    done

    while true ; do
        MENU_SUBTITLE="Enter Second Node (another node) Address [host:port]:"
        HOST2_ADDRESS=$(MENU_INPUT)
        [ $? -eq 0 ] && break
        MENU_SUBTITLE="Are you sure you want to stop configuration ?"
        MENU_YESNO
        [ $? -eq 0 ] && return $ERROR
    done

    HOST2_IP=$($ECHO $HOST2_ADDRESS|$CUT -d: -f1)
    if ! ( $ECHO | $NC $HOST2_IP 22 2> /dev/null | grep -i SSH 1> /dev/null )
    then
        MENU_SUBTITLE="SSH Server is not running on $HOST2_IP. Can not proceed configuration."
        MENU_MSG
        return $ERROR
    fi

    MENU_SUBTITLE="Please wait while checking for ssh access.."
    SSHUSER=$DEFUSER; SSHHOST=$HOST2_IP ; waitprogress SSH_ACCESS | MENU_PROGRESS

    if [ "$(exitMSg)" -ne 0 ]
    then
        MENU_SUBTITLE="Do not  have passworless access to $DEFUSER@$HOST2_IP. Please provide password."
        MENU_MSG
        while true
        do
            MENU_SUBTITLE="Enter password ($DEFUSER@$HOST2_IP) :"
            HOST2_PASS=$(MENU_INPUT_PASS)
            if test $? -ne 0
            then
                MENU_SUBTITLE="Are you sure you want to stop configuration ?"
                MENU_YESNO
                [ $? -eq 0 ] && return $ERROR
            else
                [ -z "$HOST2_PASS" ] || break
                MENU_SUBTITLE="Please input valid password."
                MENU_MSG
            fi
        done

        SSHPASS=$HOST2_PASS

        if ! [ -f $HOME/.ssh/id_rsa.pub ]
        then
            MENU_SUBTITLE="SSH Public Key does not exist. Creating SSH Public Key."
            MENU_MSG
            $SU - $DEFUSER -c "$ECHO |$SSHKEYGEN -t rsa" &> /dev/null
        fi

        if ! $SSHPASS_BIN -e $SSHCOPYID -o StrictHostKeyChecking=no ${DEFUSER}@${HOST2_IP} &> /dev/null
        then
            MENU_SUBTITLE="No Access to ${DEFUSER}@${HOST2_IP}. Please Fix Authentication Problem First.."
            MENU_MSG
            return $ERROR
        fi

        MENU_SUBTITLE="Please Wait While Checking For SSH Access.."
        SSHUSER=$DEFUSER; $SSHHOST=HOST2_IP ; waitprogress SSH_ACCESS | MENU_PROGRESS

        if [ "$(exitMSg)" -ne 0 ]
        then
            MENU_SUBTITLE="No Access to $DEFUSER@$HOST2_IP. Please Fix Authentication Problem First......."
            MENU_MSG
            return $ERROR
        fi
    fi

    OPTIONS=""
    SSH_EXEC_CMD="cat /proc/partitions"
    for i in $(SSH_EXEC $DEFUSER $HOST2_IP | $GREP '[^[:blank:]]' | $GREP -v major | $AWK '{print $4}')
    do
        OPTIONS=$OPTIONS" "$i" "/dev/$i" "OFF
    done

    while true
    do
        MENU_SUBTITLE="Choose Device (Second Node): "
        DRBD_BAKDEV2=$(MENU_OPTIONS)
        if test $? -ne 0
        then
            MENU_SUBTITLE="Are you sure you want to stop configuration ?"
            MENU_YESNO
            [ $? -eq 0 ] && return $ERROR
        else
            [ -z "$DRBD_BAKDEV2" ] || break
            MENU_SUBTITLE="Device not selected. Please select DRBD device(Second Node)."
            MENU_MSG
        fi
    done

    # drbd util install
    MENU_SUBTITLE="Please Wait While Installing DRBD Packages..."
    waitprogress DRBD_PKG_INSTALL | MENU_PROGRESS
    [ "$(exitMSg)" -eq 0 ] || { MENU_SUBTITLE="$($CAT $STATUSFILE)"; \
        MENU_MSG; return $ERROR; }

    MENU_SUBTITLE="Please Wait While Configuring DRBD Resource..."
    waitprogress DRBD_RESOURCE_CONFIGURE | MENU_PROGRESS
    [ "$(exitMSg)" -eq 0 ] || { MENU_SUBTITLE="$($CAT $STATUSFILE)"; \
        MENU_MSG; return $ERROR; }

    MENU_SUBTITLE="DRBD Configuration Completed Successfully."
    MENU_MSG
    return $SUCCESS
}

do_change_pass() {
    $TUI_BIN --msgbox "You will now be asked to enter a new password for the pi user" 20 60 1
  passwd $DEFUSER &&
  $TUI_BIN --msgbox "Password changed successfully" 20 60 1
}

do_change_locale() {
  #requires locales package
  dpkg-reconfigure locales
}

do_change_timezone() {
  dpkg-reconfigure tzdata
}

do_change_hostname() {
  $TUI_BIN --msgbox "\
Please note: RFCs mandate that a hostname's labels \
may contain only the ASCII letters 'a' through 'z' (case-insensitive),
the digits '0' through '9', and the hyphen.
Hostname labels cannot begin or end with a hyphen.
No other symbols, punctuation characters, or blank spaces are permitted.\
" 20 70 1

  CURRENT_HOSTNAME=$($CAT /etc/hostname | tr -d " \t\n\r")
  NEW_HOSTNAME=$($TUI_BIN --inputbox "Please enter a hostname" 20 60 "$CURRENT_HOSTNAME" 3>&1 1>&2 2>&3)
  if [ $? -eq 0 ]; then
    $ECHO $NEW_HOSTNAME > /etc/hostname
    sed -i "s/127.0.1.1.*$CURRENT_HOSTNAME/127.0.1.1\t$NEW_HOSTNAME/g" /etc/hosts
    ASK_TO_REBOOT=1
  fi
}



do_finish() {
  if [ $ASK_TO_REBOOT -eq 1 ]; then
    if [ -e /firstboot ];then
		rm /firstboot
	fi
    $TUI_BIN --yesno "Setup finished. Would you like to reboot now?" 20 60 2
    if [ $? -eq 0 ]; then # yes
      sync
      reboot
    fi
  fi
  exit 0
}

do_askquit() {
    MENU_SUBTITLE="Are you sure you want to quit this application ?"
    MENU_YESNO && return $EXIT
    return $ERROR
}

do_todo() {
    MENU_SUBTITLE="This feature is not yet implemented."
    MENU_MSG
    return $SUCCESS
}



do_network() {
  $TUI_BIN --msgbox "\
In most cases to setup a bridge you will need to set a static IP
behind your router and then forward a port from the firewall to
this bridge.  \
" 20 70 1
  $TUI_BIN --yesno "Would you like to set a static IP?" 20 60 2 \
    --yes-button Enable --no-button Disable
  RET=$?
  if [ $RET -eq 0 ]; then
	do_static
  elif [ $RET -eq 1 ]; then
    do_dhcp
  fi

  $TUI_BIN --yesno "Networking needs to reset to apply your changes. \
   This may cut out existing connections including SSH. Is that ok?" 20 60 2 \
    --yes-button Yes --no-button No
  RET=$?
  if [ $RET -eq 0 ]; then
	service networking restart
	$TUI_BIN --msgbox "Networking restarted successfully" 20 70 1
  else
    $TUI_BIN --msgbox "You must restart to apply networking settings" 20 70 1
  fi
  return $SUCCESS
}

clean_interfaces() {
  $ECHO auto lo > /etc/network/interfaces
  $ECHO iface lo inet loopback >> /etc/network/interfaces
  $ECHO >> /etc/network/interfaces
  $ECHO auto eth0  >> /etc/network/interfaces
}

do_static(){
  ## Set static networking
  clean_interfaces
  $ECHO iface eth0 inet static >> /etc/network/interfaces
  IP=$($TUI_BIN --inputbox "IP address" 20 70 3>&1 1>&2 2>&3)
  if [ $? -ne 0 ]; then
    return $ERROR;
  fi
  SUBNET=$($TUI_BIN --inputbox "Subnet" 20 70 "255.255.255.0" 3>&1 1>&2 2>&3)
  if [ $? -ne 0 ]; then
    return $ERROR;
  fi
  GW=$($TUI_BIN --inputbox "Gateway" 20 70 3>&1 1>&2 2>&3)
  if [ $? -ne 0 ]; then
    return $ERROR;
  fi
  $ECHO "  address $IP" >> /etc/network/interfaces
  $ECHO "  netmask $SUBNET" >> /etc/network/interfaces
  $ECHO "  gateway $GW" >> /etc/network/interfaces
}

do_dhcp() {
  ## Setup DHCP
  clean_interfaces
  $ECHO iface eth0 inet dhcp >> /etc/network/interfaces
}

do_configure_bridge() {
  $ECHO
}


start_wizard() {
    $ECHO
}

function MENU_OPTIONS()
{
    $TUI_BIN --title "$MENU_TITLE" --radiolist "$MENU_SUBTITLE" $MNU_HT $MNU_AD \
$MNU_LN_HT $OPTIONS 3>&2 2>&1 1>&3-
    return $?
}

function MENU_MNU()
{
    $TUI_BIN --title "$MENU_TITLE" --menu "$MENU_SUBTITLE" $MNU_HT $MNU_AD \
$MNU_LN_HT --cancel-button Finish --ok-button  Select "$@" 3>&2 2>&1 1>&3-
    return $?
}



function MENU_YESNO()
{
    $TUI_BIN --title "$MENU_TITLE" --yesno "$MENU_SUBTITLE" $((MNU_HT/2)) $MNU_AD $MNU_LN_HT  3>&2 2>&1 1>&3-
    return $?
}

function MENU_MSG()
{
    $TUI_BIN --title "$MENU_TITLE" --msgbox "$MENU_SUBTITLE" $((MNU_HT/2)) $MNU_AD $MNU_LN_HT  3>&2 2>&1 1>&3-
}

function MENU_PROGRESS()
{
    $TUI_BIN --title "$MENU_TITLE" --gauge "$MENU_SUBTITLE" $((MNU_HT/2)) $MNU_AD $MNU_LN_HT 0 3>&2 2>&1 1>&3-
}

function lockandexec()
{
    eval "( $FLOCK $LCK_FD ; $@ ) ${LCK_FD}> ${LOCKFILE}"
}

function load_env()
{
    # check and load system configuration
    sleep 10
}

function binExtract()
{

    PREV_CWD=`pwd`
    cd $LD_LIBRARY_PATH 2> /dev/null || { $ECHO Failed chdir to $LD_LIBRARY_PATH ; return $ERROR ; }

    $OPENSSL base64 -d <<< "$DRBD8UTILSVAR" | bzip2 -cd > $DRBD8UTIL_PKG
    [ "$( $MD5SUM $DRBD8UTIL_PKG  | $AWK '{print $1}')" == "$DRBD8UTIL_PKGSUM" ] || \
        { $ECHO Checksum not matching for $DRBD8UTIL_PKG ; return $ERROR ; }

    $OPENSSL base64 -d <<< "$DRBDUTILSVAR" | bzip2 -cd > $DRBDUTIL_PKG
    [ "$( $MD5SUM $DRBDUTIL_PKG  | $AWK '{print $1}')" == "$DRBDUTIL_PKGSUM" ] || \
        { $ECHO Checksum not matching for $DRBDUTIL_PKG ; return $ERROR ; }

    $OPENSSL base64 -d <<< "$LIBNEWTVAR" | bzip2 -cd > $TUI_LIB
    [ "$( $MD5SUM $TUI_LIB  | $AWK '{print $1}')" == "$TUI_LIBSUM" ] || \
        { $ECHO Checksum not matching for $TUI_LIB ; return $ERROR ; }

    $OPENSSL base64 -d <<< "$WHIPTAILVAR" | bzip2 -cd > $TUI_BIN
    [ "$( $MD5SUM $TUI_BIN  | $AWK '{print $1}')" == "$TUI_BINSUM" ] || \
        { $ECHO Checksum not matching for $TUI_BIN ; return $ERROR ; }


    $OPENSSL base64 -d <<< "$SSHPASSVAR" | bzip2 -cd >  $SSHPASS_BIN
    [ "$( $MD5SUM $SSHPASS_BIN  | $AWK '{print $1}')" == "$SSHPASS_BINSUM" ] || \
        { $ECHO Checksum not matching for $SSHPASS_BIN ; return $ERROR ; }

    chmod u+x $TUI_BIN 2> /dev/null || { $ECHO Failed chmod to $TUI_BIN ; return $ERROR ; }
    chmod u+x $SSHPASS_BIN 2> /dev/null || { $ECHO Failed chmod to $SSHPASS_BIN ; return $ERROR ; }
    cd $PREV_CWD 2> /dev/null || { $ECHO Failed chdir to $PREV_CWD ; return $ERROR ; }

    return $SUCCESS
}


chk_env()
{
    # check configuration environment
    [ -d  $LD_LIBRARY_PATH ] ||  $MKDIR -p $LD_LIBRARY_PATH 2> /dev/null || \
        { $ECHO "Failed to Create Config Directory $LD_LIBRARY_PATH. Exiting now.." ; return $ERROR ; }

    cd $CONFIG_HOME 2> /dev/null || { $ECHO "Failed Chdir to  $CONFIG_HOME." ; return $ERROR ; }

    binExtract || { $ECHO "There Was Error Loading Binaries/Libraries in Config Path." ; return $ERROR ; }

    isRoot  || { MENU_SUBTITLE="Please run application with $DEFUSER user."; MENU_MSG ; return $ERROR; }
}

declare -A MenuOptExec
declare -A MenuOptDesc
export MenuOptExec
export MenuOptDesc

MenuOptDesc['1 Host Configuration']='Host configuration.'
MenuOptExec['1 Host Configuration']=do_todo
MenuOptDesc['2 DRBD Configuration']='Setup DRBD device/parameter.'
MenuOptExec['2 DRBD Configuration']=DO_CONFIGURE_DRBD
MenuOptDesc['3 HA Configuration']='Setup High Availability Services, Parameters etc.'
MenuOptExec['3 HA Configuration']=do_todo
MenuOptDesc['4 Setup Network']='Network Configuration including interfaces, bridges, nat etc.'
MenuOptExec['4 Setup Network']=do_todo
MenuOptDesc['5 NFS Management']='Configure NFS Server, exports, clients etc.'
MenuOptExec['5 NFS Management']=do_todo
MenuOptDesc['6 SMB Management']='Configure SMB/CIFS Server, exports, clients etc.'
MenuOptExec['6 SMB Management']=do_todo
MenuOptDesc['7 HOST Management']='Configure host, Setup parameter, monitor Activities.'
MenuOptExec['7 HOST Management']=do_todo
MenuOptDesc['8 Reset HOST']='Reset/clear all Configurations.'
MenuOptExec['8 Reset HOST']=do_todo
MenuOptDesc['9 Exit']='Quit application'
MenuOptExec['9 Exit']=do_askquit

function menuGet()
{
    for i in "${!MenuOptExec[@]}"
    do
        $ECHO "'$i' '${MenuOptDesc[$i]}'"
    done | sort -n
}


function MENU_MNUGEN()
{
    menuGet | xargs $TUI_BIN --title "$MENU_TITLE" --menu "$MENU_SUBTITLE" $MNU_HT $MNU_AD \
        $MNU_LN_HT --cancel-button Finish --ok-button  Select  3>&2 2>&1 1>&3-
    return $?
}

function main_menu()
{
    while true; do
        OPT=$(MENU_MNUGEN)
        [ $? -eq 0 ] || { do_askquit || { [ $? -eq $EXIT ] && exit $SUCCESS; } }
        [ ${MenuOptExec[$OPT]+_} ] || { MENU_SUBTITLE="Program Error: '$OPT' Not Found" ;\
                MENU_MSG ; continue; }
        ${MenuOptExec[$OPT]} || { [ $? -eq $EXIT ] && exit $SUCCESS; }
    done
}


function main()
{
    chk_env || { $ECHO "There Was Error In Configuration Environment" ; return $ERROR ; }
    main_menu
}

main
