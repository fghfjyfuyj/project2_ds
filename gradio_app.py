import gradio as gr
from app import solve_quiz  # Import your existing function

iface = gr.Interface(
    fn=solve_quiz,
    inputs=[
        gr.Textbox(label="Email"),
        gr.Textbox(label="Secret"),
        gr.Textbox(label="Quiz URL")
    ],
    outputs=gr.JSON(label="Answer")
)

iface.launch(server_name="0.0.0.0", server_port=7860)

