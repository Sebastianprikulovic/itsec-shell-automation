#!/bin/bash

inputfile="sample.log"
logfile="analysis.log"

log() {
echo "$(date) - $1" | tee -a $logfile
}

failed_count=0
error_count=0
unauth_count=0

while read -r line; do

if echo "$line" | grep -qi "failed"; then
    log "Misslyckat inloggningsförsök: $line"
    ((failed_count++))
fi

if echo "$line" | grep -qi "error"; then
    log "Error hittad: $line"
    ((error_count++))
fi

if echo "$line" | grep -qi "unauthorized"; then
    log "Obehörigt försök: $line"
    ((unauth_count++))
fi

done < "$inputfile"

log "ANALYS KLAR"
log "Antal misslyckade inloggningar: $failed_count"
log "Antal errors: $error_count"
log "Antal obehöriga försök: $unauth_count"
