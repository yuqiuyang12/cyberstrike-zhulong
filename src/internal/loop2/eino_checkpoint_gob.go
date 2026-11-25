package loop2

import "encoding/gob"

// Eino ADK 的 ChatModelAgent 在其 graph 内无条件挂
//
//	compose.WithCheckPointID(bridgeCheckpointID)  // 常量 "adk_react_mock_key"
//	compose.WithSerializer(&gobSerializer{})      // 标准 encoding/gob
//
// （见 eino v0.9.14: adk/chatmodel.go Run/Resume + adk/interrupt.go bridgeCheckpointID）
//
// 因此只要 run 被中断（对话页「停止」/「中断并继续」/ TurnLoop preempt），
// 整个 compose checkpoint（State + Channels + Inputs + 子图）都会被 gob 编码。
// gob 的规则是：interface 槽位里装的具体类型必须事先注册，否则报
//
//	gob: type not registered for interface: map[string]interface {}
//
// 并被包成 "failed to set checkpoint: ..., checkPointID: adk_react_mock_key"，
// 直接让整轮对话失败（2026-10-15 / 10-22 x2 / 10-28 共四次线上事故）。
//
// 触发这类值的最常见来源是 JSON 解码结果：消息 Extra、工具/中间件元数据、会话上下文
// 只要经过一次 JSON 往返，就会从具体类型退化成 map[string]interface{} / []interface{}。
// 标准库只给基本类型预注册，不包含这两个容器类型，故在此显式注册。
//
// 上游同源问题（截至 eino v0.9.22 仍未修）：
//   - cloudwego/eino#1399 typed-nil 导致 checkpoint 编码失败
//   - cloudwego/eino#1405 SessionValues 携带结构化 JSON 导致 checkpoint 编码失败
//   - cloudwego/eino#1240 agent event 内 gob 不安全的值
//
// 升级依赖不能消除本缺陷，注册是最小且向后兼容的修法（已注册类型名与默认名一致，
// 旧 checkpoint 仍可用；重复 Register 幂等）。
//
// 回归护栏：internal/loop2/eino_checkpoint_gob_test.go
func init() {
	gob.Register(map[string]interface{}{})
	gob.Register([]interface{}{})
}
