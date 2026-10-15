"""Author deterministic labeled test scenarios; labels do not call the detector."""
import json
from datetime import datetime,timedelta,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def build():
    cases=[]
    for rule in ['ROLL-001','ROLL-002','ROLL-003']:
        for positive in [True,False]:
            for variant in range(12):
                base=datetime(2026,10,1,tzinfo=timezone.utc)+timedelta(hours=variant,seconds=298)
                def row(n,sec,action='failure',user='alex',ip='203.0.113.10'):
                    return {'event_id':f'e{n}','timestamp':(base+timedelta(seconds=sec)).isoformat(),
                            'username':user,'src_ip':ip,'action':action,'geo':'US-NC'}
                reason=''
                if rule=='ROLL-001':
                    rows=[row(i,i*(variant+1)) for i in range(5 if positive else 4)]
                    reason='Five failures cross a fixed-bin boundary' if positive else 'Four failures stay below threshold'
                    if not positive and variant%2:
                        rows=[row(i,i*301) for i in range(5)];reason='Failures are outside rolling window'
                elif rule=='ROLL-002':
                    rows=[row(i,i) for i in range(3)]
                    rows.append(row(3,3+variant,'success'))
                    reason='Success after three recent failures'
                    if not positive:
                        mode=variant%4
                        if mode==0:rows[-1]=row(3,-1,'success');reason='Success precedes failures'
                        if mode==1:rows[-1]=row(3,303,'success');reason='Failures expired'
                        if mode==2:rows[-1]=row(3,10,'success',user='other');reason='Different user'
                        if mode==3:rows[-1]=row(3,10,'success',ip='192.0.2.9');reason='Different source'
                else:
                    rows=[row(i,i*(variant+1),user=f'user{i if positive else i%4}') for i in range(5)]
                    reason='Five distinct targeted users' if positive else 'Only four distinct users'
                    if not positive and variant%2:
                        rows=[row(i,i*601,user=f'user{i}') for i in range(5)];reason='Distinct users outside time window'
                cases.append({'case_id':f'{rule}-{int(positive)}-{variant:02}',
                              'target_rule':rule,'expected_positive':positive,'rationale':reason,'events':rows})
    return cases

if __name__=='__main__':
    p=ROOT/'lab/fixtures/benchmark/scenarios.json'
    p.write_text(json.dumps(build(),indent=2)+'\n')
    print('Wrote 72 deterministic labeled scenarios')
