#!/usr/bin/env python3
"""
修改 panel.sh 添加多 IP 切换功能和流量狗按钮
"""
import re

def main():
    # 读取文件
    with open('panel.sh', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 修改 1: 添加 RemoteTarget 结构体 (在 Rule 结构体之前)
    # 查找 "struct Rule {" 并在其前面添加 RemoteTarget
    remote_target_struct = '''#[derive(Serialize, Deserialize, Clone, Debug)]
struct RemoteTarget {
    address: String,
    #[serde(default)]
    label: String,
}

'''
    if 'struct RemoteTarget' not in content:
        content = content.replace(
            'struct Rule {',
            remote_target_struct + 'struct Rule {'
        )
        print("[OK] Added RemoteTarget struct")
    
    # 修改 2: 在 Rule 结构体中添加 remote_list 字段
    # 在 "remote: String," 后添加 remote_list
    if 'remote_list: Vec<RemoteTarget>' not in content:
        content = re.sub(
            r'(remote: String,)',
            r'\1\n    #[serde(default)]\n    remote_list: Vec<RemoteTarget>,',
            content
        )
        print("[OK] Added remote_list field to Rule struct")
    
    # 修改 3: 添加 API 路由 (在现有路由后)
    new_routes = '''.route("/api/rules/:id/targets", get(get_rule_targets).post(add_rule_target))
        .route("/api/rules/:id/targets/:idx", delete(delete_rule_target))
        .route("/api/rules/:id/switch-target", post(switch_rule_target))'''
    
    if '/api/rules/:id/targets' not in content:
        # 在 .route("/api/restore" 之前添加
        content = content.replace(
            '.route("/api/restore"',
            new_routes + '\n        .route("/api/restore"'
        )
        print("[OK] Added API routes")
    
    # 修改 4: 添加 API 处理函数 (在 update_bg 函数之后)
    api_handlers = '''

// 多目标切换 API
async fn get_rule_targets(Path(id): Path<String>, cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter().find(|r| r.id == id) {
        Json(serde_json::json!({"targets": rule.remote_list})).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Deserialize)]
struct AddTargetReq { address: String, label: String }

async fn add_rule_target(Path(id): Path<String>, cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<AddTargetReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        rule.remote_list.push(RemoteTarget { address: req.address, label: req.label });
        save_json(&data);
        Json(serde_json::json!({"status":"ok"})).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn delete_rule_target(Path((id, idx)): Path<(String, usize)>, cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        if idx < rule.remote_list.len() {
            rule.remote_list.remove(idx);
            save_json(&data);
            Json(serde_json::json!({"status":"ok"})).into_response()
        } else {
            Json(serde_json::json!({"status":"error","message":"索引超出范围"})).into_response()
        }
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Deserialize)]
struct SwitchTargetReq { index: usize }

async fn switch_rule_target(Path(id): Path<String>, cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<SwitchTargetReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) {
        if req.index < rule.remote_list.len() {
            rule.remote = rule.remote_list[req.index].address.clone();
            save_json(&data);
            drop(data);
            let _ = reload_realm(&state);
            Json(serde_json::json!({"status":"ok"})).into_response()
        } else {
            Json(serde_json::json!({"status":"error","message":"索引超出范围"})).into_response()
        }
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
'''
    
    if 'async fn get_rule_targets' not in content:
        # 在 update_bg 函数结束后添加
        content = re.sub(
            r'(async fn update_bg.*?\.into_response\(\)\n\})',
            r'\1' + api_handlers,
            content,
            flags=re.DOTALL
        )
        print("[OK] Added API handlers")
    
    # 修改 5: 在导航栏添加流量狗按钮
    if 'openTrafficDog()' not in content:
        content = content.replace(
            '<button class="btn btn-gray" onclick="openSettings()">',
            '<button class="btn btn-gray" onclick="openTrafficDog()" style="background:#f59e0b;color:white"><i class="fas fa-dog"></i> <span class="nav-text">流量狗</span></button><button class="btn btn-gray" onclick="openSettings()">'
        )
        print("[OK] Added Traffic Dog button")
    
    # 修改 6: 在编辑弹窗中添加多目标管理区域
    if 'targetsSection' not in content:
        # 在 mod_r 输入框后添加
        content = content.replace(
            '<input id="mod_r"><label>到期时间',
            '<input id="mod_r"><div id="targetsSection" style="display:none;margin:15px 0;padding:15px;border:1px dashed #ddd;border-radius:10px;background:rgba(0,0,0,0.02)"><label style="display:flex;justify-content:space-between;align-items:center">备用目标列表 <button type="button" class="btn btn-gray" style="padding:4px 10px;font-size:0.8rem" onclick="addTargetRow()"><i class="fas fa-plus"></i> 添加</button></label><div id="targetsList"></div></div><label>到期时间'
        )
        print("[OK] Added multi-target section")
    
    # 修改 7: 修改 render() 函数添加目标下拉选择
    if 'quickSwitch' not in content:
        # 在 render 函数中，找到 targetHtml 的定义位置并修改
        old_target = "let tfStr = fmtBytes(r.traffic_used);"
        new_target = '''let targetHtml=r.remote;if(r.remote_list&&r.remote_list.length>0){const opts=r.remote_list.map((t,i)=>`<option value="${i}" ${t.address===r.remote?'selected':''}>${t.label||t.address}</option>`).join('');targetHtml=`<select onchange="quickSwitch('${r.id}',this.value)" style="padding:4px 8px;border-radius:6px;border:1px solid rgba(0,0,0,0.1);background:rgba(255,255,255,0.8);font-size:0.85rem;max-width:150px"><option value="-1">${r.remote}</option>${opts}</select>`;}
let tfStr = fmtBytes(r.traffic_used);'''
        if 'targetHtml' not in content:
            content = content.replace(old_target, new_target)
            print("[OK] Added target dropdown")
    
    # 修改 8: 在规则表格中使用 targetHtml
    if '${targetHtml}' not in content:
        content = content.replace(
            '<td data-label="目标">${r.remote}</td>',
            '<td data-label="目标">${targetHtml}</td>'
        )
        print("[OK] Updated table to use targetHtml")
    
    # 修改 9: 修改 openAddModal 和 openEdit 函数
    if "targetsSection').style.display='none'" not in content:
        content = content.replace(
            "$('ruleModal').style.display='flex'}",
            "$('targetsSection').style.display='none';$('targetsList').innerHTML='';$('ruleModal').style.display='flex'}"
        )
        print("[OK] Modified openAddModal function")
    
    if "targetsSection').style.display='block'" not in content:
        content = content.replace(
            "$('mod_reset_day').value=r.reset_day||0;$('ruleModal').style.display='flex'}",
            "$('mod_reset_day').value=r.reset_day||0;$('targetsSection').style.display='block';loadTargets(id);$('ruleModal').style.display='flex'}"
        )
        print("[OK] Modified openEdit function")
    
    # 修改 10: 添加多目标管理 JavaScript 函数
    js_functions = '''
let curTargets=[];
async function loadTargets(id){const r=await fetch(`/api/rules/${id}/targets`);if(!r.ok)return;const d=await r.json();curTargets=d.targets||[];renderTargets();}
function renderTargets(){const t=$('targetsList');t.innerHTML='';curTargets.forEach((tgt,i)=>{const div=document.createElement('div');div.style='display:flex;gap:8px;align-items:center;margin-top:8px';div.innerHTML=`<input value="${tgt.address}" placeholder="目标地址" style="flex:2" onchange="curTargets[${i}].address=this.value"><input value="${tgt.label||''}" placeholder="标签(可选)" style="flex:1" onchange="curTargets[${i}].label=this.value"><button type="button" class="btn btn-danger" style="padding:6px 10px" onclick="removeTarget(${i})"><i class="fas fa-times"></i></button><button type="button" class="btn btn-primary" style="padding:6px 10px" onclick="switchToTarget(${i})" title="切换到此目标"><i class="fas fa-exchange-alt"></i></button>`;t.appendChild(div);});}
function addTargetRow(){curTargets.push({address:'',label:''});renderTargets();}
function removeTarget(idx){curTargets.splice(idx,1);renderTargets();}
async function switchToTarget(idx){if(!curId||idx<0||idx>=curTargets.length)return;const tgt=curTargets[idx];if(!tgt.address){alert('目标地址不能为空');return;}if(!confirm(`确定切换到 ${tgt.label||tgt.address}？`))return;const r=await fetch(`/api/rules/${curId}/switch-target`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:idx})});const d=await r.json();if(d.status==='ok'){alert('切换成功');closeModal();load();}else{alert(d.message||'切换失败');}}
async function saveTargetsForRule(){if(!curId)return;for(const t of curTargets){if(!t.address)continue;await fetch(`/api/rules/${curId}/targets`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:t.address,label:t.label||''})});}}
async function quickSwitch(ruleId,idx){idx=parseInt(idx);if(idx<0)return;const r=await fetch(`/api/rules/${ruleId}/switch-target`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:idx})});const d=await r.json();if(d.status==='ok'){load();}else{alert(d.message||'切换失败');}}
function openTrafficDog(){alert('流量狗功能：请在终端执行 bash port-traffic-dog.sh 进入端口流量监控管理');}
'''
    
    if 'async function loadTargets' not in content:
        # 在 setInterval(load, 3000) 之前添加
        content = content.replace(
            'setInterval(load, 3000);',
            js_functions + '\nsetInterval(load, 3000);'
        )
        print("[OK] Added multi-target JavaScript functions")
    
    # 写回文件
    with open('panel.sh', 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)
    
    print("\n[DONE] All modifications completed!")

if __name__ == '__main__':
    main()
