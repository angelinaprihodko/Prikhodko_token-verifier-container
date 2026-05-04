from django.shortcuts import render
from sympy import symbols
import time, hashlib, hmac, base64, json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io, base64 as b64
import numpy as np

TOKEN_SECRET_KEY = ""
TTL = 600

t_sym, TTL_sym, t0_sym = symbols('t_sym TTL_sym t0_sym')
validity_remaining_expr = TTL_sym - (t_sym - t0_sym)
validity_pct_expr = validity_remaining_expr / TTL_sym * 100


def generate_token(user_id, role, offset=0):
    now = int(time.time()) + offset
    payload = {"user_id": user_id, "role": role, "iat": now, "exp": now + TTL}
    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode().rstrip("=")
    if TOKEN_SECRET_KEY:
        signature = hmac.new(TOKEN_SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    else:
        signature = hashlib.sha256(payload_b64.encode()).hexdigest()
    return f"{payload_b64}.{signature}", now


def verify_token(token):
    """
    Трёхуровневая верификация маркера аутентификации.
    Уровень 1 — Структура (формат и декодирование)
    Уровень 2 — Целостность (проверка подписи SHA-256)
    Уровень 3 — Срок действия (iat/exp относительно текущего времени)
    """
    result = {
        "valid": False,
        "reason": "",
        "payload": None,
        "level1_pass": False,
        "level2_pass": False,
        "level3_pass": False,
        "level_failed": 0,
        "details": ""
    }
    current_time = int(time.time())

    # === УРОВЕНЬ 1: Структура маркера ===
    parts = token.split(".")
    if len(parts) != 2:
        result["reason"] = "Отклонён на Уровне 1: неверная структура маркера (отсутствует разделитель)"
        result["level_failed"] = 1
        result["details"] = "Ожидается формат: <payload_base64>.<signature_hex>"
        return result

    payload_b64, received_signature = parts[0], parts[1]

    padding = 4 - len(payload_b64) % 4
    test_b64 = payload_b64
    if padding != 4:
        test_b64 += "=" * padding
    try:
        payload = json.loads(base64.urlsafe_b64decode(test_b64).decode())
    except Exception:
        result["reason"] = "Отклонён на Уровне 1: ошибка декодирования полезной нагрузки"
        result["level_failed"] = 1
        result["details"] = "Полезная нагрузка не является допустимым base64-кодированным JSON"
        return result

    result["level1_pass"] = True

    # === УРОВЕНЬ 2: Проверка подписи (целостность) ===
    if TOKEN_SECRET_KEY:
        expected_signature = hmac.new(TOKEN_SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    else:
        expected_signature = hashlib.sha256(payload_b64.encode()).hexdigest()

    if not hmac.compare_digest(expected_signature, received_signature):
        result["reason"] = "Отклонён на Уровне 2: подпись недействительна (маркер подделан или повреждён)"
        result["level_failed"] = 2
        result["details"] = f"Контрольная сумма не совпадает. Целостность маркера нарушена."
        result["payload"] = payload
        return result

    result["level2_pass"] = True

    # === УРОВЕНЬ 3: Срок действия ===
    if current_time > payload["exp"]:
        result["reason"] = "Отклонён на Уровне 3: срок действия маркера истёк"
        result["level_failed"] = 3
        result["details"] = f"Маркер просрочен на {current_time - payload['exp']} сек."
        result["payload"] = payload
        return result
    if current_time < payload["iat"]:
        result["reason"] = "Отклонён на Уровне 3: время выпуска маркера в будущем"
        result["level_failed"] = 3
        result["details"] = f"Время выпуска ({payload['iat']}) позже текущего ({current_time}) на {payload['iat'] - current_time} сек."
        result["payload"] = payload
        return result

    result["level3_pass"] = True

    # === ВСЕ УРОВНИ ПРОЙДЕНЫ ===
    result["valid"] = True
    result["reason"] = "Верифицирован: все уровни пройдены. Маркер подлинный."
    result["details"] = f"Оставшийся срок действия: {payload['exp'] - current_time} сек."
    result["payload"] = payload
    result["current_time"] = current_time
    return result


def fig_to_base64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    img_b64 = b64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)
    return img_b64


def index(request):
    current_time = int(time.time())

    # === ФОРМИРУЕМ 10 ОБРАЗЦОВЫХ МАРКЕРОВ (без указания типа в label!) ===
    sample_tokens = []

    # Маркер 1
    t, _ = generate_token("user_A7X", "analyst", offset=0)
    sample_tokens.append({"label": "Маркер №1", "token": t})

    # Маркер 2
    t, _ = generate_token("user_B3Q", "operator", offset=-200)
    sample_tokens.append({"label": "Маркер №2", "token": t})

    # Маркер 3
    t, _ = generate_token("user_C9M", "viewer", offset=-400)
    sample_tokens.append({"label": "Маркер №3", "token": t})

    # Маркер 4 (почти истёк)
    t, _ = generate_token("user_D4K", "analyst", offset=-580)
    sample_tokens.append({"label": "Маркер №4", "token": t})

    # Маркер 5 (просрочен)
    t, _ = generate_token("user_E1P", "operator", offset=-(TTL + 120))
    sample_tokens.append({"label": "Маркер №5", "token": t})

    # Маркер 6 (сильно просрочен)
    t, _ = generate_token("user_F8L", "viewer", offset=-(TTL * 2))
    sample_tokens.append({"label": "Маркер №6", "token": t})

    # Маркер 7 (подделанная подпись)
    t, _ = generate_token("user_G2V", "analyst", offset=0)
    t_tampered = t[:-6] + "FF0000"
    sample_tokens.append({"label": "Маркер №7", "token": t_tampered})

    # Маркер 8 (подмена содержимого — роль изменена на admin)
    t, iat = generate_token("user_H5W", "analyst", offset=0)
    parts = t.split(".")
    forged_payload = base64.urlsafe_b64encode(
        json.dumps({"user_id": "user_H5W", "role": "admin", "iat": iat, "exp": iat + TTL},
                   separators=(",", ":")).encode()
    ).decode().rstrip("=")
    t_forged = forged_payload + "." + parts[1]
    sample_tokens.append({"label": "Маркер №8", "token": t_forged})

    # Маркер 9 (сломана структура — нет точки)
    t, _ = generate_token("user_J3N", "viewer", offset=0)
    t_bad = t.replace(".", "!!!")
    sample_tokens.append({"label": "Маркер №9", "token": t_bad})

    # Маркер 10 (испорчен base64)
    t, _ = generate_token("user_K7R", "operator", offset=0)
    parts = t.split(".")
    t_bad_b64 = "!!!invalid-base64@@@." + parts[1]
    sample_tokens.append({"label": "Маркер №10", "token": t_bad_b64})

    # === ОБРАБОТКА ВВОДА ===
    input_token = ""
    check_result = None

    if request.method == 'POST':
        input_token = request.POST.get('token', '').strip()
        if input_token:
            check_result = verify_token(input_token)
            check_result["current_time"] = current_time

    # === ПОСТРОЕНИЕ ГРАФИКОВ ===
    chart1 = ""; chart2 = ""; chart3 = ""

    if check_result:
        # График 1: столбцы по уровням (пройден/заблокирован)
        levels = ["Уровень 1\nСтруктура", "Уровень 2\nПодпись SHA-256", "Уровень 3\nСрок действия"]
        passed = [check_result["level1_pass"], check_result["level2_pass"], check_result["level3_pass"]]
        colors_bar = ["#2ecc71" if p else "#e74c3c" for p in passed]
        labels_bar = ["Пройден" if p else "ЗАБЛОКИРОВАН" for p in passed]

        fig1, ax1 = plt.subplots(figsize=(7, 4))
        bars = ax1.bar(levels, [1 if p else 0 for p in passed], color=colors_bar, edgecolor="black", width=0.5)
        for bar, lbl in zip(bars, labels_bar):
            ax1.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.03, lbl,
                     ha="center", va="bottom", fontsize=13, fontweight="bold",
                     color="#1e8449" if "Пройден" in lbl else "#922b21")
        ax1.set_ylim(0, 1.5)
        ax1.set_ylabel("Статус проверки")
        ax1.set_title("График 1. Прохождение уровней верификации маркера")
        ax1.set_yticks([])
        fig1.tight_layout()
        chart1 = fig_to_base64(fig1)

        # График 2: матрица прохождения уровней (КАК НА ВАШЕМ ФОТО)
        level_names = ["Уровень 1\nСтруктура", "Уровень 2\nПодпись SHA-256", "Уровень 3\nСрок действия"]

        # Определяем состояние каждого уровня
        if check_result["level1_pass"] and check_result["level2_pass"] and check_result["level3_pass"]:
            # Все пройдены
            cell_states = [1, 1, 1]
        elif check_result["level_failed"] == 1:
            cell_states = [0, -1, -1]
        elif check_result["level_failed"] == 2:
            cell_states = [1, 0, -1]
        elif check_result["level_failed"] == 3:
            cell_states = [1, 1, 0]
        else:
            cell_states = [1, 1, 1]

        color_map = {1: "#2ecc71", 0: "#e74c3c", -1: "#bdc3c7"}
        label_map = {1: "Пройден", 0: "Заблокирован", -1: "Не достигнут"}

        fig2, ax2 = plt.subplots(figsize=(8, 2.5))
        for ci, state in enumerate(cell_states):
            ax2.add_patch(plt.Rectangle((ci, 0), 1, 1, color=color_map[state], ec="white", lw=2))
            ax2.text(ci+0.5, 0.5, label_map[state], ha="center", va="center", fontsize=11, fontweight="bold", color="black")

        ax2.set_xlim(0, 3)
        ax2.set_ylim(0, 1)
        ax2.set_xticks([0.5, 1.5, 2.5])
        ax2.set_xticklabels(level_names, fontsize=10)
        ax2.set_yticks([])
        ax2.set_title("График 2. Матрица прохождения уровней верификации контейнера\n(по проверенному маркеру)")
        ax2.tick_params(length=0)
        fig2.tight_layout()
        chart2 = fig_to_base64(fig2)

        # График 3: временная шкала (iat, exp, now)
        if check_result.get("payload"):
            payload = check_result["payload"]
            fig3, ax3 = plt.subplots(figsize=(8, 3))
            ax3.axhline(y=0, color="gray", linewidth=1)
            ax3.plot(payload["iat"], 0, "bs", markersize=12, label=f'Выпуск (iat): {payload["iat"]}')
            ax3.plot(payload["exp"], 0, "g^", markersize=12, label=f'Истечение (exp): {payload["exp"]}')
            ax3.plot(current_time, 0, "rD", markersize=14, label=f'Текущее время (now): {current_time}')

            # Подсветка зоны
            if check_result["valid"]:
                ax3.axvspan(payload["iat"], payload["exp"], alpha=0.15, color='green', label='Срок действия (валиден)')
            else:
                if current_time > payload["exp"]:
                    ax3.axvspan(payload["exp"], current_time, alpha=0.2, color='red', label='Просроченная зона')
                elif current_time < payload["iat"]:
                    ax3.axvspan(current_time, payload["iat"], alpha=0.2, color='orange', label='Будущая зона')

            ax3.set_xlabel("Unix-время (сек)")
            ax3.set_title("График 3. Временная шкала жизни маркера")
            ax3.legend(loc='upper left', fontsize=8)
            ax3.set_yticks([])
            ax3.grid(axis="x", alpha=0.4)
            fig3.tight_layout()
            chart3 = fig_to_base64(fig3)
        else:
            fig3, ax3 = plt.subplots(figsize=(8, 3))
            ax3.text(0.5, 0.5, "Временная шкала недоступна:\nполезная нагрузка не извлечена", ha="center", va="center",
                     fontsize=13, transform=ax3.transAxes, color="#7f8c8d")
            ax3.set_title("График 3. Временная шкала жизни маркера")
            fig3.tight_layout()
            chart3 = fig_to_base64(fig3)

    else:
        # Заглушки до проверки
        for fig_id in range(1, 4):
            fig, ax = plt.subplots(figsize=(6, 3))
            ax.text(0.5, 0.5, "Ожидание маркера...\nВыберите маркер из списка или введите вручную\nи нажмите «Проверить маркер»",
                    ha="center", va="center", fontsize=12, transform=ax.transAxes, color="#7f8c8d")
            ax.set_title(f"График {fig_id}")
            fig.tight_layout()
            if fig_id == 1: chart1 = fig_to_base64(fig)
            elif fig_id == 2: chart2 = fig_to_base64(fig)
            else: chart3 = fig_to_base64(fig)

    context = {
        "sample_tokens": sample_tokens,
        "input_token": input_token,
        "check_result": check_result,
        "chart1": chart1,
        "chart2": chart2,
        "chart3": chart3,
    }
    return render(request, "index.html", context)