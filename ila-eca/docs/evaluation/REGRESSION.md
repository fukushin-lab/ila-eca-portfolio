# 現行固定版の模擬回帰試験

対象: ILA_ECA_SHARED_POLICIES_20261121。生成モデルへの実送信・実サービス操作を伴わない試験です。

| 条件 | 結果 |
|---|---|
| 提供されたWindows実行記録 | Python 742件、失敗0、エラー0、既知スキップ1。JavaScript 31件成功 |
| この整理前に行ったLinuxでの再確認 | Windows専用4件を除いた738件を実行し、737件成功・既知スキップ1。JavaScript 31件成功 |

Linuxで対象外にした4件はPowerShellのACL確認とWindowsログオンAPIの試験です。
全回帰試験環境は別管理し、公開版には次の代表的な既存テストをそのまま掲載しています。

| 代表テスト | 確認する内容 |
|---|---|
| [test_cloud_generation.py](../../tests/unit/test_cloud_generation.py) | 外部送信条件、原応答保存、結果不明時の再送防止、文書との対応 |
| [test_g_each_capacity.py](../../tests/unit/test_g_each_capacity.py) | Terraformのeach.valueのスコープ・依存、容量設定と他経路の分離 |
| [test_shared_artifact_boundary.py](../../tests/unit/test_shared_artifact_boundary.py) | 共通のJSON・構造検査、資料の範囲・原文・ハッシュ、入力契約と表示状態 |

全体試験の件数は、ここに掲載した3ファイルだけの試験件数ではありません。

公開用に抜粋した上記3モジュールは、今回の整理後に検証環境の依存を使って再実行し、50件すべて成功しました。公開ZIPに依存環境や全試験ハーネスを含めたという意味ではありません。
