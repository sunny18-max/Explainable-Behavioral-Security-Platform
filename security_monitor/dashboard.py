from __future__ import annotations

import tkinter as tk
from collections import deque
from tkinter import messagebox, ttk

from .config import MonitorConfig
from .models import BehaviorProfile, CycleOutcome
from .service import MonitorService


class SimpleLineChart(ttk.Frame):
    def __init__(self, parent: tk.Misc, title: str, color: str) -> None:
        super().__init__(parent)
        self.color = color
        self._values: list[float] = []
        ttk.Label(self, text=title, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.canvas = tk.Canvas(
            self,
            height=150,
            background="#ffffff",
            highlightthickness=1,
            highlightbackground="#d6d6d6",
        )
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", self._redraw)

    def draw(self, values: list[float], max_value: float | None = None) -> None:
        self._values = list(values)
        self._render(max_value=max_value)

    def _redraw(self, _event: object) -> None:
        self._render()

    def _render(self, max_value: float | None = None) -> None:
        self.canvas.delete("all")
        width = max(self.canvas.winfo_width(), 240)
        height = max(self.canvas.winfo_height(), 120)
        padding = 20
        self.canvas.create_rectangle(
            padding,
            padding,
            width - padding,
            height - padding,
            outline="#eeeeee",
        )
        if not self._values:
            self.canvas.create_text(
                width / 2,
                height / 2,
                text="No data yet",
                fill="#707070",
                font=("Segoe UI", 10),
            )
            return

        local_max = max_value if max_value is not None else max(self._values) or 1.0
        local_max = max(local_max, 1.0)
        step_x = (width - 2 * padding) / max(len(self._values) - 1, 1)
        points: list[float] = []
        for index, value in enumerate(self._values):
            x = padding + index * step_x
            y = height - padding - ((value / local_max) * (height - 2 * padding))
            points.extend([x, y])

        if len(points) >= 4:
            self.canvas.create_line(*points, fill=self.color, width=2, smooth=True)
        for index in range(0, len(points), 2):
            self.canvas.create_oval(
                points[index] - 2,
                points[index + 1] - 2,
                points[index] + 2,
                points[index + 1] + 2,
                fill=self.color,
                outline="",
            )
        self.canvas.create_text(
            width - padding,
            padding / 2,
            text=f"max {local_max:.1f}",
            fill="#707070",
            font=("Segoe UI", 9),
        )


class Dashboard:
    feature_labels = {
        "typing_speed": "Typing speed",
        "typing_gap_variance": "Typing rhythm variance",
        "mouse_speed": "Mouse speed",
        "app_switch_count": "App switch count",
        "unique_app_count": "Unique app count",
        "login_hour": "Login hour",
        "session_duration_minutes": "Session duration",
        "activity_intensity": "Activity intensity",
    }

    def __init__(self, root: tk.Tk, service: MonitorService, config: MonitorConfig) -> None:
        self.root = root
        self.service = service
        self.config = config
        self.root.title(config.app_name)
        self.root.geometry("1380x860")
        self.root.minsize(1180, 720)
        self.root.configure(background="#f5f6f8")
        self._after_id: str | None = None
        self._running = False
        self._risk_history: deque[float] = deque(maxlen=config.chart_history_limit)
        self._typing_history: deque[float] = deque(maxlen=config.chart_history_limit)

        self.mode_var = tk.StringVar(value=self.service.mode)
        self.user_var = tk.StringVar(value=self.service.user_name)
        self.phase_var = tk.StringVar(value="Idle")
        self.risk_var = tk.StringVar(value="0.0")
        self.severity_var = tk.StringVar(value="normal")
        self.status_var = tk.StringVar(
            value="Ready. Start monitoring or switch to demo mode for guided anomaly scenarios."
        )
        self.profile_var = tk.StringVar(value="0 baseline samples")

        self._build_ui()
        self._refresh_user_choices()

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("Panel.TLabelframe", background="#ffffff")
        style.configure("Panel.TLabelframe.Label", font=("Segoe UI", 10, "bold"))

        container = ttk.Frame(self.root, padding=16)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=3)
        container.columnconfigure(1, weight=2)
        container.rowconfigure(1, weight=1)

        control_frame = ttk.Frame(container, style="Card.TFrame", padding=14)
        control_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        for column_index in range(8):
            control_frame.columnconfigure(column_index, weight=1)

        ttk.Label(control_frame, text="User Profile").grid(row=0, column=0, sticky="w")
        self.user_combo = ttk.Combobox(control_frame, textvariable=self.user_var, state="normal")
        self.user_combo.grid(row=1, column=0, padx=(0, 8), sticky="ew")
        ttk.Button(control_frame, text="Switch User", command=self._switch_user).grid(
            row=1, column=1, padx=(0, 8), sticky="ew"
        )

        ttk.Label(control_frame, text="Mode").grid(row=0, column=2, sticky="w")
        self.mode_combo = ttk.Combobox(
            control_frame,
            textvariable=self.mode_var,
            values=("live", "demo"),
            state="readonly",
        )
        self.mode_combo.grid(row=1, column=2, padx=(0, 8), sticky="ew")
        self.mode_combo.bind("<<ComboboxSelected>>", self._switch_mode)

        self.start_button = ttk.Button(
            control_frame,
            text="Start Monitoring",
            command=self._toggle_monitoring,
        )
        self.start_button.grid(row=1, column=3, padx=(0, 8), sticky="ew")

        ttk.Button(control_frame, text="Analyze Now", command=self._analyze_once).grid(
            row=1, column=4, padx=(0, 8), sticky="ew"
        )

        ttk.Label(control_frame, text="Demo Scenario").grid(row=0, column=5, sticky="w")
        self.scenario_combo = ttk.Combobox(
            control_frame,
            values=(
                "normal",
                "fast_typing",
                "unfamiliar_app",
                "off_hours_login",
                "combined_attack",
            ),
            state="readonly",
        )
        self.scenario_combo.set("combined_attack")
        self.scenario_combo.grid(row=1, column=5, padx=(0, 8), sticky="ew")
        ttk.Button(control_frame, text="Queue Scenario", command=self._queue_scenario).grid(
            row=1, column=6, padx=(0, 8), sticky="ew"
        )
        ttk.Label(
            control_frame,
            textvariable=self.status_var,
            wraplength=300,
            justify="left",
        ).grid(row=0, column=7, rowspan=2, sticky="ew")

        left_column = ttk.Frame(container)
        left_column.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        left_column.columnconfigure(0, weight=1)
        left_column.rowconfigure(2, weight=1)
        left_column.rowconfigure(3, weight=1)

        summary_frame = ttk.Frame(left_column, style="Card.TFrame", padding=14)
        summary_frame.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        for column_index in range(4):
            summary_frame.columnconfigure(column_index, weight=1)

        self._make_metric(summary_frame, "Phase", self.phase_var, 0)
        self._make_metric(summary_frame, "Risk Score", self.risk_var, 1)
        self._make_metric(summary_frame, "Severity", self.severity_var, 2)
        self._make_metric(summary_frame, "Baseline", self.profile_var, 3)

        chart_frame = ttk.Frame(left_column, style="Card.TFrame", padding=14)
        chart_frame.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        chart_frame.columnconfigure(0, weight=1)
        chart_frame.columnconfigure(1, weight=1)
        self.risk_chart = SimpleLineChart(chart_frame, "Risk Trend", "#c0392b")
        self.risk_chart.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.typing_chart = SimpleLineChart(chart_frame, "Typing Speed Trend", "#2471a3")
        self.typing_chart.grid(row=0, column=1, sticky="nsew")

        feature_frame = ttk.LabelFrame(
            left_column,
            text="Current Feature Snapshot",
            style="Panel.TLabelframe",
            padding=10,
        )
        feature_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 12))
        feature_frame.columnconfigure(0, weight=1)
        feature_frame.rowconfigure(0, weight=1)
        self.feature_tree = ttk.Treeview(
            feature_frame,
            columns=("feature", "current", "baseline"),
            show="headings",
            height=10,
        )
        self.feature_tree.heading("feature", text="Feature")
        self.feature_tree.heading("current", text="Current")
        self.feature_tree.heading("baseline", text="Baseline")
        self.feature_tree.column("feature", width=190)
        self.feature_tree.column("current", width=120)
        self.feature_tree.column("baseline", width=140)
        self.feature_tree.grid(row=0, column=0, sticky="nsew")
        feature_scrollbar = ttk.Scrollbar(
            feature_frame,
            orient="vertical",
            command=self.feature_tree.yview,
        )
        feature_scrollbar.grid(row=0, column=1, sticky="ns")
        self.feature_tree.configure(yscrollcommand=feature_scrollbar.set)

        notes_frame = ttk.LabelFrame(
            left_column,
            text="Collector Notes",
            style="Panel.TLabelframe",
            padding=10,
        )
        notes_frame.grid(row=3, column=0, sticky="nsew")
        notes_frame.columnconfigure(0, weight=1)
        notes_frame.rowconfigure(0, weight=1)
        self.notes_text = tk.Text(
            notes_frame,
            wrap="word",
            height=7,
            relief="flat",
            background="#ffffff",
            font=("Segoe UI", 10),
        )
        self.notes_text.grid(row=0, column=0, sticky="nsew")

        right_column = ttk.Frame(container)
        right_column.grid(row=1, column=1, sticky="nsew")
        right_column.columnconfigure(0, weight=1)
        right_column.rowconfigure(0, weight=1)
        right_column.rowconfigure(1, weight=1)

        explanation_frame = ttk.LabelFrame(
            right_column,
            text="Explanation Engine",
            style="Panel.TLabelframe",
            padding=10,
        )
        explanation_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 12))
        explanation_frame.columnconfigure(0, weight=1)
        explanation_frame.rowconfigure(1, weight=1)
        self.summary_label = ttk.Label(
            explanation_frame,
            text="No analysis yet.",
            wraplength=460,
            justify="left",
            font=("Segoe UI", 11, "bold"),
        )
        self.summary_label.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.explanation_text = tk.Text(
            explanation_frame,
            wrap="word",
            relief="flat",
            background="#ffffff",
            font=("Segoe UI", 10),
        )
        self.explanation_text.grid(row=1, column=0, sticky="nsew")

        alerts_frame = ttk.LabelFrame(
            right_column,
            text="Recent Alerts",
            style="Panel.TLabelframe",
            padding=10,
        )
        alerts_frame.grid(row=1, column=0, sticky="nsew")
        alerts_frame.columnconfigure(0, weight=1)
        alerts_frame.rowconfigure(0, weight=1)
        self.alert_tree = ttk.Treeview(
            alerts_frame,
            columns=("time", "severity", "risk", "summary"),
            show="headings",
            height=10,
        )
        self.alert_tree.heading("time", text="Time")
        self.alert_tree.heading("severity", text="Severity")
        self.alert_tree.heading("risk", text="Risk")
        self.alert_tree.heading("summary", text="Summary")
        self.alert_tree.column("time", width=140)
        self.alert_tree.column("severity", width=90)
        self.alert_tree.column("risk", width=70)
        self.alert_tree.column("summary", width=330)
        self.alert_tree.grid(row=0, column=0, sticky="nsew")
        alert_scrollbar = ttk.Scrollbar(
            alerts_frame,
            orient="vertical",
            command=self.alert_tree.yview,
        )
        alert_scrollbar.grid(row=0, column=1, sticky="ns")
        self.alert_tree.configure(yscrollcommand=alert_scrollbar.set)

    def _make_metric(
        self,
        parent: ttk.Frame,
        title: str,
        variable: tk.StringVar,
        column_index: int,
    ) -> None:
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.grid(row=0, column=column_index, sticky="ew", padx=6)
        ttk.Label(frame, text=title, font=("Segoe UI", 9)).pack(anchor="w")
        ttk.Label(frame, textvariable=variable, font=("Segoe UI", 16, "bold")).pack(
            anchor="w", pady=(4, 0)
        )

    def _toggle_monitoring(self) -> None:
        if self._running:
            self._running = False
            self.service.stop()
            self.start_button.configure(text="Start Monitoring")
            self.status_var.set("Monitoring stopped.")
            if self._after_id is not None:
                self.root.after_cancel(self._after_id)
                self._after_id = None
            return

        self.service.start()
        self._running = True
        self.start_button.configure(text="Stop Monitoring")
        self.status_var.set("Monitoring active. The next analysis cycle is scheduled.")
        self._schedule_next(0)

    def _switch_mode(self, _event: object | None = None) -> None:
        new_mode = self.mode_var.get()
        self.service.switch_mode(new_mode)
        self.status_var.set(
            "Demo mode uses synthetic scenarios with seeded baseline behavior."
            if new_mode == "demo"
            else "Live mode collects real user timing and active window telemetry."
        )

    def _switch_user(self) -> None:
        self.service.switch_user(self.user_var.get())
        self.user_var.set(self.service.user_name)
        self._refresh_user_choices()
        self.status_var.set(f"Switched to user profile '{self.service.user_name}'.")

    def _refresh_user_choices(self) -> None:
        self.user_combo["values"] = self.service.list_users()

    def _queue_scenario(self) -> None:
        if self.mode_var.get() != "demo":
            messagebox.showinfo("Demo mode required", "Switch the dashboard to demo mode first.")
            return
        scenario_name = self.scenario_combo.get()
        self.service.queue_demo_scenario(scenario_name)
        self.status_var.set(f"Queued demo scenario '{scenario_name}'.")

    def _schedule_next(self, delay_ms: int) -> None:
        self._after_id = self.root.after(delay_ms, self._analysis_tick)

    def _analysis_tick(self) -> None:
        self._analyze_once()
        if self._running:
            self._schedule_next(self.config.analysis_interval_seconds * 1000)

    def _analyze_once(self) -> None:
        try:
            outcome = self.service.collect_once()
        except Exception as error:  # pragma: no cover - UI surface
            self.status_var.set(f"Analysis failed: {error}")
            return
        self._render_outcome(outcome)
        if outcome.detection.is_anomaly:
            self.root.bell()

    def _render_outcome(self, outcome: CycleOutcome) -> None:
        detection = outcome.detection
        self.phase_var.set("Suspicious" if detection.is_anomaly else "Monitoring")
        if detection.training_mode:
            self.phase_var.set("Training")
        self.risk_var.set(f"{detection.risk_score:.1f}")
        self.severity_var.set(detection.severity)
        self.profile_var.set(f"{outcome.profile.sample_count} baseline samples")
        self.summary_label.configure(text=detection.summary)
        self.status_var.set(
            f"{outcome.mode.title()} mode for '{outcome.user_name}'. "
            f"Observed app: {outcome.features.dominant_app}."
        )

        self._risk_history.append(detection.risk_score)
        self._typing_history.append(outcome.features.typing_speed)
        self.risk_chart.draw(list(self._risk_history), max_value=100.0)
        historical_typing = [sample.typing_speed for sample in outcome.recent_history]
        self.typing_chart.draw(historical_typing or list(self._typing_history))

        self._populate_feature_tree(outcome.profile, outcome)
        self._populate_explanations(outcome)
        self._populate_alerts(outcome)
        self._populate_notes(outcome.collector_notes)

    def _populate_feature_tree(
        self,
        profile: BehaviorProfile,
        outcome: CycleOutcome,
    ) -> None:
        self.feature_tree.delete(*self.feature_tree.get_children())
        for field_name, label in self.feature_labels.items():
            current_value = getattr(outcome.features, field_name)
            baseline = profile.baselines.get(field_name)
            baseline_value = "learning" if baseline is None else f"{baseline.mean:.2f}"
            self.feature_tree.insert(
                "",
                "end",
                values=(label, self._format_value(current_value), baseline_value),
            )

    def _populate_explanations(self, outcome: CycleOutcome) -> None:
        self.explanation_text.configure(state="normal")
        self.explanation_text.delete("1.0", tk.END)
        self.explanation_text.insert(tk.END, outcome.detection.explanation + "\n\n")
        if outcome.detection.reasons:
            self.explanation_text.insert(tk.END, "Why it looks suspicious:\n")
            for reason in outcome.detection.reasons:
                self.explanation_text.insert(tk.END, f"- {reason}\n")
        else:
            self.explanation_text.insert(tk.END, "No alert reasons to show yet.\n")
        self.explanation_text.configure(state="disabled")

    def _populate_alerts(self, outcome: CycleOutcome) -> None:
        self.alert_tree.delete(*self.alert_tree.get_children())
        for alert in outcome.recent_alerts:
            self.alert_tree.insert(
                "",
                "end",
                values=(
                    alert.created_at.strftime("%H:%M:%S"),
                    alert.severity,
                    f"{alert.risk_score:.1f}",
                    alert.summary,
                ),
            )

    def _populate_notes(self, notes: list[str]) -> None:
        self.notes_text.configure(state="normal")
        self.notes_text.delete("1.0", tk.END)
        if notes:
            self.notes_text.insert(tk.END, "\n".join(f"- {note}" for note in notes))
        else:
            self.notes_text.insert(tk.END, "No collector notes for this cycle.")
        self.notes_text.configure(state="disabled")

    @staticmethod
    def _format_value(value: float | int) -> str:
        if isinstance(value, int):
            return str(value)
        return f"{value:.2f}"
