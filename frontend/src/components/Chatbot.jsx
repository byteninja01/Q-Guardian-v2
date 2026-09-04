import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import { MessageSquare, X, Send, Bot, ShieldCheck } from 'lucide-react';
import { API_BASE } from '../lib/api.js';

const Chatbot = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState([
        { role: 'bot', text: 'Hello! I am the Q-Guardian intelligence assistant. I analyze your scans locally without external models. How can I help you today?' }
    ]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const messagesEndRef = useRef(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const handleSend = async (text) => {
        const query = text || input;
        if (!query.trim()) return;

        setMessages(prev => [...prev, { role: 'user', text: query }]);
        setInput('');
        setIsTyping(true);

        try {
            const res = await axios.post(`${API_BASE}/chat`, { message: query });
            setTimeout(() => {
                setMessages(prev => [...prev, { role: 'bot', text: res.data.reply }]);
                setIsTyping(false);
            }, 500); // Small artificial delay for natural feel
        } catch (err) {
            setIsTyping(false);
            setMessages(prev => [...prev, { role: 'bot', text: "Sorry, I am currently offline or disconnected from the engine." }]);
        }
    };

    return (
        <div className="fixed bottom-12 right-6 z-50">
            {/* Chatbot Button */}
            {!isOpen && (
                <button 
                    onClick={() => setIsOpen(true)}
                    className="bg-pnb-maroon text-white p-4 rounded-full shadow-2xl hover:bg-pnb-maroon/90 transition-transform transform hover:scale-105 border-2 border-pnb-gold"
                >
                    <MessageSquare size={24} />
                    <div className="absolute -top-2 -right-2 bg-red-500 w-3 h-3 rounded-full animate-ping"></div>
                    <div className="absolute -top-2 -right-2 bg-red-500 w-3 h-3 rounded-full"></div>
                </button>
            )}

            {/* Chatbot Window */}
            {isOpen && (
                <div className="w-80 sm:w-96 h-[500px] glass-card flex flex-col overflow-hidden shadow-2xl animate-in slide-in-from-bottom-10 fade-in duration-300 border-pnb-maroon">
                    {/* Header */}
                    <div className="bg-pnb-maroon text-white p-4 flex justify-between items-center border-b-2 border-pnb-gold">
                        <div className="flex items-center gap-2">
                            <Bot size={20} className="text-pnb-gold" />
                            <div>
                                <h3 className="font-black text-sm tracking-widest">Q-GUARDIAN AI</h3>
                                <p className="text-[9px] text-pnb-gold">ON-DEVICE SECURE ENGINE</p>
                            </div>
                        </div>
                        <button onClick={() => setIsOpen(false)} className="hover:bg-white/20 p-1 rounded transition-colors">
                            <X size={18} />
                        </button>
                    </div>

                    {/* Messages Area */}
                    <div className="flex-1 p-4 overflow-y-auto bg-slate-50 space-y-4">
                        {messages.map((msg, i) => (
                            <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                <div className={`max-w-[85%] text-sm p-3 rounded-lg shadow-sm ${
                                    msg.role === 'user' 
                                        ? 'bg-pnb-maroon text-white rounded-tr-none' 
                                        : 'bg-white text-slate-800 border border-slate-200 rounded-tl-none leading-relaxed'
                                }`}>
                                    {msg.text}
                                </div>
                            </div>
                        ))}
                        {isTyping && (
                            <div className="flex justify-start">
                                <div className="bg-white p-3 rounded-lg rounded-tl-none border border-slate-200 shadow-sm flex items-center gap-1">
                                    <div className="w-2 h-2 bg-pnb-maroon rounded-full animate-bounce"></div>
                                    <div className="w-2 h-2 bg-pnb-maroon rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                                    <div className="w-2 h-2 bg-pnb-maroon rounded-full animate-bounce" style={{animationDelay: '0.4s'}}></div>
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Quick Queries */}
                    <div className="px-4 py-2 bg-slate-100 flex gap-2 overflow-x-auto scrollbar-hide border-t border-slate-200">
                        <button onClick={() => handleSend("What is MOSCA?")} className="shrink-0 text-[10px] font-bold bg-white text-pnb-maroon border border-pnb-maroon rounded-full px-3 py-1 hover:bg-pnb-maroon hover:text-white transition-colors">What is MOSCA?</button>
                        <button onClick={() => handleSend("Scan results")} className="shrink-0 text-[10px] font-bold bg-white text-pnb-maroon border border-pnb-maroon rounded-full px-3 py-1 hover:bg-pnb-maroon hover:text-white transition-colors">Latest Scan</button>
                        <button onClick={() => handleSend("Are we RBI compliant?")} className="shrink-0 text-[10px] font-bold bg-white text-pnb-maroon border border-pnb-maroon rounded-full px-3 py-1 hover:bg-pnb-maroon hover:text-white transition-colors">RBI Compliance</button>
                    </div>

                    {/* Input Area */}
                    <div className="p-3 bg-white border-t border-slate-200 flex gap-2">
                        <input 
                            type="text" 
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyPress={(e) => e.key === 'Enter' && handleSend()}
                            placeholder="Ask me anything..."
                            className="flex-1 text-sm px-3 py-2 bg-slate-100 rounded-md focus:outline-none focus:ring-1 focus:ring-pnb-maroon"
                        />
                        <button 
                            onClick={() => handleSend()}
                            disabled={!input.trim()}
                            className="bg-pnb-maroon text-white p-2 rounded-md disabled:opacity-50 hover:bg-pnb-maroon/90 transition-colors"
                        >
                            <Send size={18} />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Chatbot;
