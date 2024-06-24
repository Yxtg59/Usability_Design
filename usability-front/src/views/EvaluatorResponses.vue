<script setup>
import { ref, onMounted } from 'vue';
import axios from 'axios';
import { useRoute, useRouter } from 'vue-router';

// Obtiene el ID de la prueba desde la ruta y el ID del evaluador desde el LocalStorage
const route = useRoute();
const router = useRouter();
const testId = route.params.testId;
const evaluatorId = ref(localStorage.getItem('user_id'));

// Variables reactivas para los cuestionarios, las respuestas y el estado de envío
const questionnaires = ref([]);
const responses = ref({});
const allResponsesCompleted = ref(false);
const responsesSubmitted = ref(false);

// Al montar el componente, verifica el estado de envío y carga los cuestionarios y respuestas guardadas si no se han enviado
onMounted(async () => {
  await checkSubmissionStatus();
  if (!responsesSubmitted.value) {
    await loadQuestionnaires();
    await loadSavedResponses();
    checkAllResponsesCompleted();
  }
});

// Verifica si el evaluador ya ha enviado todas las respuestas
const checkSubmissionStatus = async () => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/designtests/${testId}/check_submission`, {
      params: {
        evaluator_id: evaluatorId.value
      }
    });
    if (response.status === 200) {
      responsesSubmitted.value = response.data.submitted;
      if (responsesSubmitted.value) {
        router.push('/designtests/access');
      }
    }
  } catch (error) {
    console.error('Error:', error);
  }
};

// Carga los cuestionarios
const loadQuestionnaires = async () => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/designtests/${testId}/questionnaires`);
    if (response.status === 200) {
      questionnaires.value = response.data;
      response.data.forEach(q => {
        responses.value[q.questionnaire_id] = {
          response_value: null,
          respuesta: '',
          url_frame: q.url_frame,
          evaluator_id: evaluatorId.value,
          test_id: testId,
          response_type: q.response_type
        };
      });
    }
  } catch (error) {
    console.error('Error:', error);
  }
};

// Carga las respuestas guardadas
const loadSavedResponses = async () => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/questionnaires/responses/${evaluatorId.value}/${testId}`);
    if (response.status === 200) {
      response.data.forEach(r => {
        if (responses.value[r.questionnaire_id]) {
          responses.value[r.questionnaire_id].response_value = r.response_value;
          responses.value[r.questionnaire_id].respuesta = r.respuesta;
        }
      });
      checkAllResponsesCompleted();
    }
  } catch (error) {
    console.error('Error:', error);
  }
};

// Guarda una respuesta específica del cuestionario
const saveResponse = async (questionnaireId) => {
  try {
    await axios.post(`http://127.0.0.1:5000/questionnaires/${questionnaireId}/responses`, responses.value[questionnaireId]);
    alert('Respuesta guardada exitosamente');
    checkAllResponsesCompleted();
  } catch (error) {
    console.error('Error:', error);
    alert('Ocurrió un error al guardar la respuesta.');
  }
};

// Verifica si todas las respuestas están completas
const checkAllResponsesCompleted = () => {
  allResponsesCompleted.value = questionnaires.value.every(q => {
    const response = responses.value[q.questionnaire_id];
    return response.response_value !== null && response.respuesta.trim() !== '';
  });
};

// Envía todas las respuestas
const submitAllResponses = async () => {
  try {
    await axios.post('http://127.0.0.1:5000/submit_responses', {
      evaluator_id: evaluatorId.value,
      test_id: testId
    });
    alert('Todas las respuestas han sido enviadas.');
    responsesSubmitted.value = true;
    router.push('/designtests/access');
  } catch (error) {
    console.error('Error:', error);
    alert('Ocurrió un error al enviar las respuestas.');
  }
};
</script>

<template>
  <div class="container mt-4" style="width: 10000px;">
    <h2 class="mb-4">Responder Cuestionarios</h2>
    <div v-if="responsesSubmitted">
      <p class="text-danger text-center fs-1">Ya has enviado todas las respuestas para esta prueba de diseño.</p>
    </div>
    <div v-else-if="questionnaires.length > 0" >
      <div v-for="questionnaire in questionnaires" :key="questionnaire.questionnaire_id" class="card mb-3">
        <div class="card-body d-flex" >
          <div class="questionnaire-info">
            <h5 class="card-title">{{ questionnaire.title }}</h5>
            <p class="card-text">{{ questionnaire.description }}</p>
            <div v-if="questionnaire.response_type === 'Calificación'">
              <label>Calificación:</label>
              <div class="radio-group">
                <div v-for="n in 10" :key="n" class="radio-item">
                  <input type="radio" :id="'calificacion' + questionnaire.questionnaire_id + n" :value="n" 
                         v-model="responses[questionnaire.questionnaire_id].response_value">
                  <label :for="'calificacion' + questionnaire.questionnaire_id + n">{{ n }}</label>
                </div>
              </div>
            </div>
            <div v-else-if="['Legibilidad', 'Coherencia'].includes(questionnaire.response_type)">
              <label>{{ questionnaire.response_type }}:</label>
              <div class="radio-group">
                <div v-for="n in 5" :key="n" class="radio-item">
                  <input type="radio" :id="'legibilidad-coherencia' + questionnaire.questionnaire_id + n" :value="n" 
                         v-model="responses[questionnaire.questionnaire_id].response_value">
                  <label :for="'legibilidad-coherencia' + questionnaire.questionnaire_id + n">{{ n }}</label>
                </div>
              </div>
            </div>
            <div>
              <label>Respuesta:</label>
              <textarea v-model="responses[questionnaire.questionnaire_id].respuesta" class="form-control"></textarea>
            </div>
            <button @click="saveResponse(questionnaire.questionnaire_id)" class="btn btn-primary mt-3">Guardar Respuesta</button>
          </div>
          <div class="iframe-container ms-3">
            <iframe :src="responses[questionnaire.questionnaire_id].url_frame" width="110%" height="800" frameborder="0"></iframe>
          </div>
        </div>
      </div>
      <button @click="submitAllResponses" class="btn btn-success mt-3" :disabled="!allResponsesCompleted">Enviar Todas las Respuestas</button>
    </div>
    <div v-else>
      <p>No se encontraron cuestionarios para esta prueba de diseño.</p>
    </div>
  </div>
</template>

<style scoped>
.card {
  margin-top: 20px;
}
.radio-group {
  display: flex;
  justify-content: left;
  align-items: center;
  margin-top: 10px;
}

.radio-item {
  margin: 0 10px;
  display: flex;
  flex-direction: column;
  align-items: center;
}
.d-flex {
  display: flex;
}
.ms-3 {
  margin-left: 1rem;
}
.questionnaire-info {
  flex: 1;
  width: 25%; /* Ocupa el 25% del ancho del card */
}
.iframe-container {
  flex: 3;
  width: 75%; /* Ocupa el 75% del ancho del card */
  border: 1px solid #ccc;
  overflow: hidden;
}
</style>