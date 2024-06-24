<script setup>
import { ref, onMounted } from 'vue';
import axios from 'axios';
import { useRoute } from 'vue-router';
import pdfMake from 'pdfmake/build/pdfmake';
import pdfFonts from 'pdfmake/build/vfs_fonts';
 
pdfMake.vfs = pdfFonts.pdfMake.vfs;
 
const route = useRoute();
const testId = route.params.testId;
 
const responses = ref([]);
const iframeStyle = ref({});
const containerStyle = ref({});
 
onMounted(async () => {
  await loadResponses();
  setIframeStyles();
});
 
const loadResponses = async () => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/designtests/${testId}/responses`);
    if (response.status === 200) {
      responses.value = response.data;
      setIframeStyles();
    }
  } catch (error) {
    console.error('Error:', error);
  }
};
 
const setIframeStyles = () => {
  const testType = localStorage.getItem('testType');
  if (testType === 'Movil') {
    iframeStyle.value = {
      width: '640px',
      height: '1310px'
    };
    containerStyle.value = {
      width: '1180px',
      height: '1380px'
    };
  } else if (testType === 'Web') {
    iframeStyle.value = {
      width: '1746px',
      height: '1242px'
    };
    containerStyle.value = {
      width: '1786px',
      height: '1312px'
    };
  } else if (testType === 'Tablet') {
    iframeStyle.value = {
      width: '980px',
      height: '1404px'
    };
    containerStyle.value = {
      width: '1020px',
      height: '1474px'
    };
  }
};
 
// Función para convertir imagen de URL a base64
const getBase64ImageFromURL = (url) => {
  return new Promise((resolve, reject) => {
    var img = new Image();
    img.crossOrigin = 'Anonymous';
    img.onload = function() {
      var canvas = document.createElement('canvas');
      canvas.width = this.width;
      canvas.height = this.height;
 
      var ctx = canvas.getContext('2d');
      ctx.drawImage(this, 0, 0);
 
      var dataURL = canvas.toDataURL('image/png');
      resolve(dataURL);
    };
    img.onerror = function() {
      reject(new Error('Failed to load image'));
    };
    img.src = url;
  });
};
 
const exportPDF = async () => {
  try {
    const imageUrl = 'https://www.figma.com/embed?embed_host=share&url=https%3A%2F%2Fwww.figma.com%2Fproto%2FIxAxTkDbFHgejdGmbwfrVH%2FGreeland%3Fnode-id%3D265-874%26starting-point-node-id%3D849%253A744%26t%3DCak4mDDUI6ZEfm8G-1';
    const base64Image = await getBase64ImageFromURL(imageUrl);
 
    const docDefinition = {
      content: [
        { text: 'Respuestas del Cuestionario', style: 'header' },
        ...responses.value.map(response => ({
          style: 'response',
          table: {
            widths: ['*'],
            body: [
              [{ text: `Título: ${response.questionnaire_title}`, style: 'subheader' }],
              [{ text: `Descripción: ${response.questionnaire_description}` }],
              [{ text: `Evaluador: ${response.evaluator_username}` }],
              [{ text: `Valor de Respuesta: ${response.response_value}` }],
              [{ text: `Respuesta: ${response.respuesta}` }],
              [{ text: `Fecha de Respuesta: ${response.created_at}` }],
              [{ text: 'Imagen de ejemplo:', style: 'subheader' }],
              [{ image: base64Image, width: 150 }]
            ]
          },
          layout: 'noBorders'
        }))
      ],
      styles: {
        header: {
          fontSize: 18,
          bold: true,
          marginBottom: 10
        },
        subheader: {
          fontSize: 15,
          bold: true,
          marginBottom: 5
        },
        response: {
          marginBottom: 15
        }
      }
    };
 
    pdfMake.createPdf(docDefinition).download('RespuestasCuestionario.pdf');
  } catch (error) {
    console.error('Error:', error);
  }
};
</script>
 
<template>
<div class="container mt-4">
<h2 class="mb-4 text-center">Respuestas del Cuestionario</h2>
<div v-if="responses.length > 0">
<button @click="exportPDF" class="btn btn-primary mb-4">Exportar a PDF</button>
<div v-for="response in responses" :key="response.response_id" class="m-4 d-flex justify-content-center">
<div class="card mb-3" :style="containerStyle">
<div class="card-header">
<h5 class="card-title m-1">{{ response.questionnaire_title }}</h5>
</div>
<div class="card-body d-flex justify-content-between">
<div class="response-details">
<p class="card-text"><strong>Descripción:</strong> {{ response.questionnaire_description }}</p>
<p class="card-text"><strong>Evaluador:</strong> {{ response.evaluator_username }}</p>
<p class="card-text"><strong>Valor de Respuesta:</strong> {{ response.response_value }}</p>
<p class="card-text"><strong>Respuesta:</strong> {{ response.respuesta }}</p>
<p class="card-text"><strong>Fecha de Respuesta:</strong> {{ response.created_at }}</p>
</div>
<div class="iframe-container">
<iframe :src="response.url_frame" :style="iframeStyle" frameborder="0" allowfullscreen></iframe>
</div>
</div>
</div>
</div>
</div>
<div v-else>
<p class="text-center text-muted">No se encontraron respuestas para esta prueba de diseño.</p>
</div>
</div>
</template>
 
<style scoped>
.container {
  margin-top: 20px;
}
 
.card-header {
  background-color: #f8f9fa;
}
 
.card {
  border: 1px solid #dee2e6;
}
 
.response-details {
  flex: 1;
  margin-right: 20px;
}
 
.iframe-container {
  flex-shrink: 0;
}
</style>