import gradio as gr
from app import solve_quiz  # your existing function

iface = gr.Interface(
    fn=solve_quiz,
    inputs=[
        gr.Textbox(label="Email"),
        gr.Textbox(label="Secret"),
        gr.Textbox(label="Quiz URL")
    ],
    outputs=gr.JSON(label="Answer")
)

iface.launch()
